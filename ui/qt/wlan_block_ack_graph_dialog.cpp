/* wlan_block_ack_graph_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wlan_block_ack_graph_dialog.h"

#include <algorithm>

#include <epan/epan_dissect.h>
#include <epan/ftypes/ftypes.h>
#include <epan/packet.h>
#include <epan/proto.h>

#include <QAction>
#include <QByteArray>
#include <QCheckBox>
#include <QComboBox>
#include <QDialogButtonBox>
#include <QDir>
#include <QHash>
#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QPushButton>
#include <QVector>
#include <QVBoxLayout>

#include "main_application.h"
#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/utils/tango_colors.h>
#include <ui/qt/widgets/qcp_axis_ticker_si.h>
#include <ui/qt/widgets/qcustomplot.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>

namespace {

constexpr uint32_t basic_block_ack = 0;
constexpr uint32_t extended_compressed_block_ack = 1;
constexpr uint32_t compressed_block_ack = 2;
constexpr uint32_t multi_tid_block_ack = 3;

using FieldIds = QVector<int>;
using FieldInfos = QVector<const field_info *>;

struct BaSample {
    uint32_t frame_number = 0;
    double relative_time = 0.0;
    uint32_t type = 0;
    uint32_t tid = 0;
    uint32_t starting_sequence = 0;
    QByteArray bitmap;
};

struct BaSession {
    QString ta;
    QString ra;
    uint32_t tid = 0;
    QVector<BaSample> samples;
};

struct BaStaPair {
    QString ta;
    QString ra;
    QVector<int> session_indexes;
};

static FieldIds fieldIdsByName(const char *name)
{
    FieldIds ids;
    const header_field_info *field = proto_registrar_get_byname(name);
    while (field) {
        ids.append(field->id);
        if (field->same_name_prev_id < 0) {
            break;
        }
        field = proto_registrar_get_nth(field->same_name_prev_id);
    }
    return ids;
}

static FieldInfos fieldInfos(epan_dissect *edt, const FieldIds &hf_ids)
{
    FieldInfos result;
    if (!edt || !edt->tree) {
        return result;
    }

    for (int hf_id : hf_ids) {
        GPtrArray *fields = proto_get_finfo_ptr_array(edt->tree, hf_id);
        if (fields) {
            for (unsigned i = 0; i < fields->len; i++) {
                result.append(static_cast<const field_info *>(fields->pdata[i]));
            }
        }
    }

    if (!result.isEmpty()) {
        return result;
    }

    // The tap filter primes these fields. Retain a fallback for callers which
    // dissect with a full protocol tree instead.
    for (int hf_id : hf_ids) {
        GPtrArray *fields = proto_find_first_finfo(edt->tree, hf_id);
        if (fields) {
            for (unsigned i = 0; i < fields->len; i++) {
                result.append(static_cast<const field_info *>(fields->pdata[i]));
            }
            g_ptr_array_free(fields, true);
        }
    }
    return result;
}

static QVector<uint32_t> unsignedFieldValues(epan_dissect *edt, const FieldIds &hf_ids)
{
    QVector<uint32_t> values;
    for (const field_info *field : fieldInfos(edt, hf_ids)) {
        values.append(fvalue_get_uinteger(field->value));
    }
    return values;
}

static QVector<QByteArray> byteFieldValues(epan_dissect *edt, const FieldIds &hf_ids)
{
    QVector<QByteArray> values;
    for (const field_info *field : fieldInfos(edt, hf_ids)) {
        const uint8_t *data = static_cast<const uint8_t *>(
                    fvalue_get_bytes_data(field->value));
        size_t size = fvalue_get_bytes_size(field->value);
        if (data && size > 0) {
            values.append(QByteArray(reinterpret_cast<const char *>(data),
                                     static_cast<int>(size)));
        }
    }
    return values;
}

static QString sessionKey(const QString &ta, const QString &ra, uint32_t tid)
{
    return QStringLiteral("%1|%2|%3").arg(ta, ra).arg(tid);
}

static QString blockAckTypeName(uint32_t type)
{
    switch (type) {
    case basic_block_ack:
        return QObject::tr("Basic");
    case extended_compressed_block_ack:
        return QObject::tr("Extended Compressed");
    case compressed_block_ack:
        return QObject::tr("Compressed");
    case multi_tid_block_ack:
        return QObject::tr("Multi-TID");
    default:
        return QObject::tr("Unsupported (%1)").arg(type);
    }
}

static bool bitmapPositionSet(const BaSample &sample, int position)
{
    const uint8_t *bitmap = reinterpret_cast<const uint8_t *>(sample.bitmap.constData());
    if (sample.type == basic_block_ack) {
        int byte_offset = position * 2;
        if (byte_offset + 1 >= sample.bitmap.size()) {
            return false;
        }
        uint16_t fragments = static_cast<uint16_t>(bitmap[byte_offset]) |
                (static_cast<uint16_t>(bitmap[byte_offset + 1]) << 8);
        return fragments != 0;
    }

    int byte_offset = position / 8;
    if (byte_offset >= sample.bitmap.size()) {
        return false;
    }
    return (bitmap[byte_offset] & (1U << (position % 8))) != 0;
}

static int bitmapPositionCount(const BaSample &sample)
{
    // A Basic BA has one 16-bit fragment bitmap for each of 64 sequence
    // numbers. Compressed formats have one bit per sequence number.
    return sample.type == basic_block_ack
            ? static_cast<int>(sample.bitmap.size() / 2)
            : static_cast<int>(sample.bitmap.size() * 8);
}

static bool validBitmapSize(uint32_t type, int size)
{
    switch (type) {
    case basic_block_ack:
        return size == 128;
    case extended_compressed_block_ack:
    case multi_tid_block_ack:
        return size == 8;
    case compressed_block_ack:
        return size == 8 || size == 32 || size == 64 || size == 128;
    default:
        return false;
    }
}

static int bitmapSetBitCount(const BaSample &sample)
{
    int count = 0;
    const uint8_t *bitmap = reinterpret_cast<const uint8_t *>(sample.bitmap.constData());
    for (int i = 0; i < sample.bitmap.size(); i++) {
        uint8_t value = bitmap[i];
        while (value) {
            count += value & 1;
            value >>= 1;
        }
    }
    return count;
}

} // namespace

class WlanBlockAckGraphDialog::Private
{
public:
    Private() :
        hf_ba_type(fieldIdsByName("wlan.ba.control.ba_type")),
        hf_single_tid(fieldIdsByName("wlan.ba.basic.tidinfo")),
        hf_multi_tid(fieldIdsByName("wlan.bar.mtid.tidinfo.value")),
        hf_starting_sequence(fieldIdsByName("wlan.fixed.ssc.sequence")),
        hf_bitmap(fieldIdsByName("wlan.ba.bm"))
    {
    }

    FieldIds hf_ba_type;
    FieldIds hf_single_tid;
    FieldIds hf_multi_tid;
    FieldIds hf_starting_sequence;
    FieldIds hf_bitmap;

    QVector<BaSession> sessions;
    QVector<BaStaPair> sta_pairs;
    QHash<QString, int> session_indexes;
    QVector<int> anchor_sample_indexes;
    QVector<int> set_anchor_indexes;
    QVector<int> hole_anchor_indexes;
    QVector<QCPItemText *> ssn_labels;

    QComboBox *station_pair_combo = nullptr;
    QComboBox *tid_combo = nullptr;
    QCheckBox *show_holes = nullptr;
    QCustomPlot *plot = nullptr;
    QLabel *details_label = nullptr;
    QLabel *status_label = nullptr;
    QDialogButtonBox *button_box = nullptr;
    QCPGraph *anchor_graph = nullptr;
    QCPGraph *window_upper_graph = nullptr;
    QCPGraph *set_graph = nullptr;
    QCPGraph *hole_graph = nullptr;

    uint32_t initially_selected_frame = 0;
    uint32_t selected_frame = 0;
    int total_ba_frames = 0;
    int unsupported_ba_frames = 0;
    int malformed_ba_frames = 0;
};

WlanBlockAckGraphDialog::WlanBlockAckGraphDialog(QWidget &parent, CaptureFile &cf) :
    WiresharkDialog(parent, cf),
    d_(new Private)
{
    setWindowSubtitle(tr("WLAN Block Ack Graph"));
    loadGeometry(parent.width() * 4 / 5, parent.height() * 3 / 4);

    if (cap_file_.capFile() && cap_file_.capFile()->current_frame) {
        d_->initially_selected_frame = cap_file_.capFile()->current_frame->num;
    }

    QVBoxLayout *main_layout = new QVBoxLayout(this);
    QHBoxLayout *session_layout = new QHBoxLayout;
    QLabel *station_pair_label = new QLabel(tr("STA pair (TA → RA):"), this);
    d_->station_pair_combo = new QComboBox(this);
    d_->station_pair_combo->setObjectName(QStringLiteral("stationPairComboBox"));
    d_->station_pair_combo->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    station_pair_label->setBuddy(d_->station_pair_combo);
    QLabel *tid_label = new QLabel(tr("TID:"), this);
    d_->tid_combo = new QComboBox(this);
    d_->tid_combo->setObjectName(QStringLiteral("tidComboBox"));
    d_->tid_combo->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    tid_label->setBuddy(d_->tid_combo);
    d_->show_holes = new QCheckBox(tr("Show bitmap holes"), this);
    d_->show_holes->setObjectName(QStringLiteral("showBitmapHolesCheckBox"));
    d_->show_holes->setChecked(true);
    d_->show_holes->setToolTip(tr("Show zero bitmap positions before the highest set position. "
                                  "A zero does not prove that a frame was transmitted or lost."));
    session_layout->addWidget(station_pair_label);
    session_layout->addWidget(d_->station_pair_combo, 1);
    session_layout->addWidget(tid_label);
    session_layout->addWidget(d_->tid_combo);
    session_layout->addWidget(d_->show_holes);
    main_layout->addLayout(session_layout);

    d_->plot = new QCustomPlot(this);
    d_->plot->setObjectName(QStringLiteral("blockAckPlot"));
    d_->plot->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom | QCP::iSelectPlottables);
    d_->plot->axisRect()->setRangeDrag(Qt::Horizontal | Qt::Vertical);
    d_->plot->axisRect()->setRangeZoom(Qt::Horizontal | Qt::Vertical);
    d_->plot->axisRect()->setRangeDragAxes(d_->plot->xAxis, d_->plot->yAxis);
    d_->plot->axisRect()->setRangeZoomAxes(d_->plot->xAxis, d_->plot->yAxis);
    d_->plot->setContextMenuPolicy(Qt::ActionsContextMenu);
    d_->plot->setFocusPolicy(Qt::StrongFocus);
    d_->plot->setToolTip(
                tr("Drag to pan. Use the wheel over the plot to zoom both axes, or wheel and "
                   "drag directly over an axis to change only that axis. Shortcuts: "
                   "X / Shift+X and Y / Shift+Y."));
    d_->plot->addLayer(QStringLiteral("baSsnLabels"), d_->plot->layer(QStringLiteral("main")),
                       QCustomPlot::limBelow);
    d_->plot->xAxis->setLabel(tr("Time"));
    d_->plot->xAxis->setTicker(QSharedPointer<QCPAxisTickerSi>(
                                   new QCPAxisTickerSi(FORMAT_SIZE_UNIT_SECONDS)));
    d_->plot->xAxis->setNumberPrecision(9);
    d_->plot->yAxis->setLabel(tr("Sequence number (12-bit)"));
    d_->plot->legend->setVisible(true);
    main_layout->addWidget(d_->plot, 1);

    d_->anchor_graph = d_->plot->addGraph();
    d_->anchor_graph->setName(tr("BA starting sequence"));
    d_->anchor_graph->setLineStyle(QCPGraph::lsStepLeft);
    d_->anchor_graph->setPen(QPen(QColor(tango_sky_blue_4), 1.5));
    d_->anchor_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc,
                                                       QColor(tango_sky_blue_5),
                                                       QColor(Qt::white), 7));
    d_->anchor_graph->setSelectable(QCP::stSingleData);

    d_->window_upper_graph = d_->plot->addGraph();
    d_->window_upper_graph->setObjectName(QStringLiteral("baWindowUpperBoundGraph"));
    d_->window_upper_graph->setName(tr("BA window upper bound (exclusive)"));
    d_->window_upper_graph->setLineStyle(QCPGraph::lsStepLeft);
    d_->window_upper_graph->setPen(QPen(QColor(tango_orange_4), 1.5));
    d_->window_upper_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssDisc, QColor(tango_orange_4), 5));
    d_->window_upper_graph->setSelectable(QCP::stNone);

    d_->set_graph = d_->plot->addGraph();
    d_->set_graph->setName(tr("BA bitmap set"));
    d_->set_graph->setLineStyle(QCPGraph::lsNone);
    d_->set_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc,
                                                    QColor(tango_chameleon_5), 5));
    d_->set_graph->setSelectable(QCP::stNone);

    d_->hole_graph = d_->plot->addGraph();
    d_->hole_graph->setName(tr("BA bitmap zero before highest set"));
    d_->hole_graph->setLineStyle(QCPGraph::lsNone);
    d_->hole_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssCross,
                                                     QColor(tango_scarlet_red_3), 7));
    d_->hole_graph->setSelectable(QCP::stNone);

    d_->details_label = new QLabel(
                tr("Only Block Ack responses are analyzed. Bitmap zeros mean “not acknowledged "
                   "in this BA”; they do not prove transmission or packet loss."), this);
    d_->details_label->setObjectName(QStringLiteral("blockAckDetailsLabel"));
    d_->details_label->setWordWrap(true);
    main_layout->addWidget(d_->details_label);

    d_->status_label = new QLabel(this);
    d_->status_label->setObjectName(QStringLiteral("blockAckStatusLabel"));
    main_layout->addWidget(d_->status_label);

    d_->button_box = new QDialogButtonBox(QDialogButtonBox::Save |
                                           QDialogButtonBox::Reset |
                                           QDialogButtonBox::Close, this);
    d_->button_box->button(QDialogButtonBox::Save)->setText(tr("Save As…"));
    d_->button_box->button(QDialogButtonBox::Reset)->setText(tr("Reset Graph"));
    main_layout->addWidget(d_->button_box);

    QAction *zoom_in_x_action = new QAction(tr("Zoom In X Axis"), d_->plot);
    zoom_in_x_action->setShortcut(QKeySequence(Qt::Key_X));
    zoom_in_x_action->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    d_->plot->addAction(zoom_in_x_action);
    QAction *zoom_out_x_action = new QAction(tr("Zoom Out X Axis"), d_->plot);
    zoom_out_x_action->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_X));
    zoom_out_x_action->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    d_->plot->addAction(zoom_out_x_action);
    QAction *zoom_in_y_action = new QAction(tr("Zoom In Y Axis"), d_->plot);
    zoom_in_y_action->setShortcut(QKeySequence(Qt::Key_Y));
    zoom_in_y_action->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    d_->plot->addAction(zoom_in_y_action);
    QAction *zoom_out_y_action = new QAction(tr("Zoom Out Y Axis"), d_->plot);
    zoom_out_y_action->setShortcut(QKeySequence(Qt::SHIFT | Qt::Key_Y));
    zoom_out_y_action->setShortcutContext(Qt::WidgetWithChildrenShortcut);
    d_->plot->addAction(zoom_out_y_action);

    connect(d_->station_pair_combo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &WlanBlockAckGraphDialog::stationPairChanged);
    connect(d_->tid_combo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &WlanBlockAckGraphDialog::tidChanged);
    connect(d_->show_holes, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::bitmapHolesToggled);
    connect(d_->plot, &QCustomPlot::plottableClick,
            this, &WlanBlockAckGraphDialog::plotClicked);
    connect(zoom_in_x_action, &QAction::triggered,
            this, [this]() { zoomXAxis(true); });
    connect(zoom_out_x_action, &QAction::triggered,
            this, [this]() { zoomXAxis(false); });
    connect(zoom_in_y_action, &QAction::triggered,
            this, [this]() { zoomYAxis(true); });
    connect(zoom_out_y_action, &QAction::triggered,
            this, [this]() { zoomYAxis(false); });
    connect(d_->button_box->button(QDialogButtonBox::Save), &QPushButton::clicked,
            this, &WlanBlockAckGraphDialog::saveGraph);
    connect(d_->button_box->button(QDialogButtonBox::Reset), &QPushButton::clicked,
            this, &WlanBlockAckGraphDialog::resetAxes);
    connect(d_->button_box->button(QDialogButtonBox::Close), &QPushButton::clicked,
            this, &WlanBlockAckGraphDialog::reject);

    collectBlockAcks();
}

WlanBlockAckGraphDialog::~WlanBlockAckGraphDialog()
{
    delete d_;
}

void WlanBlockAckGraphDialog::tapReset(void *dialog_ptr)
{
    WlanBlockAckGraphDialog *dialog = static_cast<WlanBlockAckGraphDialog *>(dialog_ptr);
    if (!dialog) {
        return;
    }

    dialog->d_->sessions.clear();
    dialog->d_->sta_pairs.clear();
    dialog->d_->session_indexes.clear();
    dialog->d_->total_ba_frames = 0;
    dialog->d_->unsupported_ba_frames = 0;
    dialog->d_->malformed_ba_frames = 0;
}

tap_packet_status WlanBlockAckGraphDialog::tapPacket(void *dialog_ptr,
                                                     packet_info *pinfo,
                                                     epan_dissect *edt,
                                                     const void *, tap_flags_t)
{
    WlanBlockAckGraphDialog *dialog = static_cast<WlanBlockAckGraphDialog *>(dialog_ptr);
    if (!dialog || !pinfo || !edt) {
        return TAP_PACKET_DONT_REDRAW;
    }

    Private *d = dialog->d_;
    d->total_ba_frames++;

    if (!pinfo->dl_src.data || pinfo->dl_src.len != 6 ||
        !pinfo->dl_dst.data || pinfo->dl_dst.len != 6) {
        d->malformed_ba_frames++;
        return TAP_PACKET_DONT_REDRAW;
    }

    QVector<uint32_t> types = unsignedFieldValues(edt, d->hf_ba_type);
    QVector<uint32_t> starting_sequences = unsignedFieldValues(edt, d->hf_starting_sequence);
    QVector<QByteArray> bitmaps = byteFieldValues(edt, d->hf_bitmap);
    if (types.isEmpty()) {
        d->malformed_ba_frames++;
        return TAP_PACKET_DONT_REDRAW;
    }

    uint32_t type = types.first();
    if (type != basic_block_ack && type != extended_compressed_block_ack &&
        type != compressed_block_ack && type != multi_tid_block_ack) {
        // GCR adds a group address to its session identity, and Multi-STA
        // normally supplies only an AID for each entry. Including either in a
        // TA/RA/TID-only graph would merge distinct peers or groups.
        d->unsupported_ba_frames++;
        return TAP_PACKET_DONT_REDRAW;
    }

    QVector<uint32_t> tids = type == multi_tid_block_ack
            ? unsignedFieldValues(edt, d->hf_multi_tid)
            : unsignedFieldValues(edt, d->hf_single_tid);
    if (type != multi_tid_block_ack && tids.size() > 1) {
        tids.resize(1);
    }

    if (tids.isEmpty() || starting_sequences.isEmpty() || bitmaps.isEmpty() ||
        tids.size() != starting_sequences.size() || tids.size() != bitmaps.size()) {
        d->malformed_ba_frames++;
        return TAP_PACKET_DONT_REDRAW;
    }

    QString ta = address_to_qstring(&pinfo->dl_src);
    QString ra = address_to_qstring(&pinfo->dl_dst);
    for (int i = 0; i < tids.size(); i++) {
        BaSample sample;
        sample.frame_number = pinfo->num;
        sample.relative_time = nstime_to_sec(&pinfo->rel_ts);
        sample.type = type;
        sample.tid = tids.at(i);
        sample.starting_sequence = starting_sequences.at(i) & 0x0fff;
        sample.bitmap = bitmaps.at(i);

        // Basic BA contains 64 16-bit fragment bitmaps. Other supported BA
        // formats contain one bit per sequence number.
        if (!validBitmapSize(type, static_cast<int>(sample.bitmap.size()))) {
            d->malformed_ba_frames++;
            continue;
        }

        QString key = sessionKey(ta, ra, sample.tid);
        int session_index = d->session_indexes.value(key, -1);
        if (session_index < 0) {
            BaSession session;
            session.ta = ta;
            session.ra = ra;
            session.tid = sample.tid;
            session_index = static_cast<int>(d->sessions.size());
            d->sessions.append(session);
            d->session_indexes.insert(key, session_index);
        }
        d->sessions[session_index].samples.append(sample);
    }

    return TAP_PACKET_REDRAW;
}

void WlanBlockAckGraphDialog::tapDraw(void *dialog_ptr)
{
    WlanBlockAckGraphDialog *dialog = static_cast<WlanBlockAckGraphDialog *>(dialog_ptr);
    if (dialog) {
        dialog->populateSessions();
    }
}

void WlanBlockAckGraphDialog::collectBlockAcks()
{
    // Every field in the second clause is included to prime it in the protocol
    // tree. The subtype predicate is what admits packets: 0x19 is Block Ack,
    // while 0x18 (Block Ack Request) and all data frames are excluded.
    static const char tap_filter[] =
            "wlan.fc.type_subtype == 0x0019 && "
            "(wlan.ta || wlan.ra || wlan.ba.control.ba_type || "
            "wlan.ba.basic.tidinfo || wlan.bar.mtid.tidinfo.value || "
            "wlan.fixed.ssc.sequence || wlan.ba.bm)";

    if (!registerTapListener("wlan", this, tap_filter, TL_REQUIRES_PROTO_TREE,
                             tapReset, tapPacket, tapDraw)) {
        reject();
        return;
    }

    cap_file_.retapPackets();
    tapDraw(this);
    removeTapListeners();
}

void WlanBlockAckGraphDialog::populateSessions()
{
    int selected_session = currentSessionIndex();

    for (int session_index = 0; session_index < d_->sessions.size(); session_index++) {
        BaSession &session = d_->sessions[session_index];
        std::stable_sort(session.samples.begin(), session.samples.end(),
                         [](const BaSample &left, const BaSample &right) {
            if (left.relative_time != right.relative_time) {
                return left.relative_time < right.relative_time;
            }
            return left.frame_number < right.frame_number;
        });

        if (selected_session < 0 && d_->initially_selected_frame > 0) {
            for (const BaSample &sample : session.samples) {
                if (sample.frame_number == d_->initially_selected_frame) {
                    selected_session = session_index;
                    break;
                }
            }
        }
    }

    if (selected_session < 0 && !d_->sessions.isEmpty()) {
        selected_session = 0;
    }

    QVector<int> sorted_session_indexes;
    sorted_session_indexes.reserve(d_->sessions.size());
    for (int session_index = 0; session_index < d_->sessions.size(); session_index++) {
        sorted_session_indexes.append(session_index);
    }
    std::stable_sort(sorted_session_indexes.begin(), sorted_session_indexes.end(),
                     [this](int left_index, int right_index) {
        const BaSession &left = d_->sessions.at(left_index);
        const BaSession &right = d_->sessions.at(right_index);
        if (left.ta != right.ta) {
            return left.ta < right.ta;
        }
        if (left.ra != right.ra) {
            return left.ra < right.ra;
        }
        return left.tid < right.tid;
    });

    d_->sta_pairs.clear();
    for (int session_index : sorted_session_indexes) {
        const BaSession &session = d_->sessions.at(session_index);
        if (d_->sta_pairs.isEmpty() || d_->sta_pairs.last().ta != session.ta ||
            d_->sta_pairs.last().ra != session.ra) {
            BaStaPair pair;
            pair.ta = session.ta;
            pair.ra = session.ra;
            d_->sta_pairs.append(pair);
        }
        d_->sta_pairs.last().session_indexes.append(session_index);
    }

    bool pair_signals_blocked = d_->station_pair_combo->blockSignals(true);
    bool tid_signals_blocked = d_->tid_combo->blockSignals(true);
    d_->station_pair_combo->clear();
    d_->tid_combo->clear();
    int selected_pair = -1;
    for (int pair_index = 0; pair_index < d_->sta_pairs.size(); pair_index++) {
        const BaStaPair &pair = d_->sta_pairs.at(pair_index);
        d_->station_pair_combo->addItem(
                    tr("%1 → %2 · %n TID(s)", "",
                       static_cast<int>(pair.session_indexes.size()))
                    .arg(pair.ta, pair.ra), pair_index);
        if (pair.session_indexes.contains(selected_session)) {
            selected_pair = pair_index;
        }
    }

    if (selected_pair < 0 && !d_->sta_pairs.isEmpty()) {
        selected_pair = 0;
    }
    d_->station_pair_combo->setCurrentIndex(selected_pair);
    d_->station_pair_combo->setEnabled(selected_pair >= 0);
    populateTids(selected_session);
    d_->station_pair_combo->blockSignals(pair_signals_blocked);
    d_->tid_combo->blockSignals(tid_signals_blocked);
    drawSession();
}

void WlanBlockAckGraphDialog::populateTids(int preferred_session, int preferred_tid)
{
    bool signals_blocked = d_->tid_combo->blockSignals(true);
    d_->tid_combo->clear();

    int pair_index = d_->station_pair_combo->currentData().toInt();
    if (d_->station_pair_combo->currentIndex() < 0 ||
        pair_index < 0 || pair_index >= d_->sta_pairs.size()) {
        d_->tid_combo->setEnabled(false);
        d_->tid_combo->blockSignals(signals_blocked);
        return;
    }

    const BaStaPair &pair = d_->sta_pairs.at(pair_index);
    int selected_tid_index = -1;
    for (int session_index : pair.session_indexes) {
        const BaSession &session = d_->sessions.at(session_index);
        d_->tid_combo->addItem(
                    tr("TID %1 · %n BA(s)", "",
                       static_cast<int>(session.samples.size()))
                    .arg(session.tid), session_index);
        if (session_index == preferred_session ||
            (selected_tid_index < 0 && preferred_tid >= 0 &&
             session.tid == static_cast<uint32_t>(preferred_tid))) {
            selected_tid_index = d_->tid_combo->count() - 1;
        }
    }

    if (selected_tid_index < 0 && d_->tid_combo->count() > 0) {
        selected_tid_index = 0;
    }
    d_->tid_combo->setCurrentIndex(selected_tid_index);
    d_->tid_combo->setEnabled(selected_tid_index >= 0);
    d_->tid_combo->blockSignals(signals_blocked);
}

int WlanBlockAckGraphDialog::currentSessionIndex() const
{
    if (d_->tid_combo->currentIndex() < 0) {
        return -1;
    }
    int session_index = d_->tid_combo->currentData().toInt();
    return session_index >= 0 && session_index < d_->sessions.size()
            ? session_index : -1;
}

void WlanBlockAckGraphDialog::drawSession()
{
    uint32_t preferred_frame = d_->selected_frame > 0
            ? d_->selected_frame : d_->initially_selected_frame;
    for (QCPItemText *label : d_->ssn_labels) {
        d_->plot->removeItem(label);
    }
    d_->ssn_labels.clear();
    d_->anchor_graph->data()->clear();
    d_->anchor_graph->setSelection(QCPDataSelection());
    d_->window_upper_graph->data()->clear();
    d_->set_graph->data()->clear();
    d_->hole_graph->data()->clear();
    d_->anchor_sample_indexes.clear();
    d_->set_anchor_indexes.clear();
    d_->hole_anchor_indexes.clear();
    d_->selected_frame = 0;

    int session_index = currentSessionIndex();
    if (session_index < 0 || session_index >= d_->sessions.size()) {
        d_->show_holes->setEnabled(false);
        d_->button_box->button(QDialogButtonBox::Save)->setEnabled(false);
        d_->button_box->button(QDialogButtonBox::Reset)->setEnabled(false);
        d_->details_label->setText(
                    tr("Only Block Ack responses are analyzed. Bitmap zeros mean “not "
                       "acknowledged in this BA”; they do not prove transmission or packet loss."));
        d_->status_label->setText(
                    tr("No supported Block Ack sessions found · %1 BA frame(s) examined · "
                       "%2 unsupported · %3 malformed")
                    .arg(d_->total_ba_frames)
                    .arg(d_->unsupported_ba_frames)
                    .arg(d_->malformed_ba_frames));
        d_->plot->xAxis->setRange(0.0, 1.0);
        d_->plot->yAxis->setRange(0.0, 1.0);
        d_->plot->replot();
        return;
    }

    d_->show_holes->setEnabled(true);
    d_->button_box->button(QDialogButtonBox::Save)->setEnabled(true);
    d_->button_box->button(QDialogButtonBox::Reset)->setEnabled(true);
    const BaSession &session = d_->sessions.at(session_index);
    QVector<double> anchor_times;
    QVector<double> anchor_sequences;
    QVector<double> window_upper_times;
    QVector<double> window_upper_sequences;
    QVector<double> set_times;
    QVector<double> set_sequences;
    QVector<double> hole_times;
    QVector<double> hole_sequences;
    for (int sample_index = 0; sample_index < session.samples.size(); sample_index++) {
        const BaSample &sample = session.samples.at(sample_index);
        anchor_times.append(sample.relative_time);
        anchor_sequences.append(sample.starting_sequence);
        d_->anchor_sample_indexes.append(sample_index);
        int anchor_index = static_cast<int>(d_->anchor_sample_indexes.size()) - 1;

        int positions = bitmapPositionCount(sample);
        window_upper_times.append(sample.relative_time);
        window_upper_sequences.append(sample.starting_sequence + positions);

        QCPItemText *ssn_label = new QCPItemText(d_->plot);
        ssn_label->setObjectName(
                    QStringLiteral("baSsnLabel_%1").arg(sample.frame_number));
        ssn_label->position->setAxes(d_->plot->xAxis, d_->plot->yAxis);
        ssn_label->position->setCoords(sample.relative_time, sample.starting_sequence);
        ssn_label->setText(QString::number(sample.starting_sequence));
        ssn_label->setPositionAlignment(Qt::AlignHCenter | Qt::AlignTop);
        ssn_label->setTextAlignment(Qt::AlignHCenter);
        ssn_label->setPadding(QMargins(0, 5, 0, 0));
        QFont label_font = d_->plot->font();
        label_font.setPointSize(8);
        ssn_label->setFont(label_font);
        ssn_label->setColor(QColor(tango_sky_blue_5));
        ssn_label->setPen(Qt::NoPen);
        ssn_label->setBrush(Qt::NoBrush);
        ssn_label->setSelectable(false);
        ssn_label->setClipAxisRect(d_->plot->axisRect());
        ssn_label->setClipToAxisRect(true);
        ssn_label->setLayer(QStringLiteral("baSsnLabels"));
        d_->ssn_labels.append(ssn_label);

        int highest_set = -1;
        for (int position = positions - 1; position >= 0; position--) {
            if (bitmapPositionSet(sample, position)) {
                highest_set = position;
                break;
            }
        }

        for (int position = 0; position <= highest_set; position++) {
            if (bitmapPositionSet(sample, position)) {
                set_times.append(sample.relative_time);
                set_sequences.append(sample.starting_sequence + position);
                d_->set_anchor_indexes.append(anchor_index);
            } else {
                hole_times.append(sample.relative_time);
                hole_sequences.append(sample.starting_sequence + position);
                d_->hole_anchor_indexes.append(anchor_index);
            }
        }
    }

    d_->anchor_graph->setData(anchor_times, anchor_sequences, true);
    d_->window_upper_graph->setData(window_upper_times, window_upper_sequences, true);
    d_->set_graph->setData(set_times, set_sequences, true);
    d_->hole_graph->setData(hole_times, hole_sequences, true);
    d_->hole_graph->setVisible(d_->show_holes->isChecked());
    d_->status_label->setText(
                tr("%1 session(s) · %2 BA(s) in this session · %3 bitmap-set position(s) · "
                   "%4 bitmap hole(s) · %5 unsupported BA frame(s) · %6 malformed")
                .arg(d_->sessions.size())
                .arg(session.samples.size())
                .arg(set_times.size())
                .arg(hole_times.size())
                .arg(d_->unsupported_ba_frames)
                .arg(d_->malformed_ba_frames));

    if (!session.samples.isEmpty()) {
        int details_index = 0;
        for (int anchor_index = 0;
             anchor_index < d_->anchor_sample_indexes.size(); anchor_index++) {
            int sample_index = d_->anchor_sample_indexes.at(anchor_index);
            if (session.samples.at(sample_index).frame_number == preferred_frame) {
                details_index = anchor_index;
                break;
            }
        }
        showSampleDetails(details_index);
    }
    resetAxes();
}

void WlanBlockAckGraphDialog::showSampleDetails(int data_index)
{
    int session_index = currentSessionIndex();
    if (session_index < 0 || session_index >= d_->sessions.size() ||
        data_index < 0 || data_index >= d_->anchor_sample_indexes.size()) {
        return;
    }

    int sample_index = d_->anchor_sample_indexes.at(data_index);
    const BaSample &sample = d_->sessions.at(session_index).samples.at(sample_index);
    d_->selected_frame = sample.frame_number;

    int window_positions = bitmapPositionCount(sample);
    int upper_bound = static_cast<int>(sample.starting_sequence) + window_positions;
    int set_positions = 0;
    for (int position = 0; position < window_positions; position++) {
        set_positions += bitmapPositionSet(sample, position) ? 1 : 0;
    }

    QString bitmap_detail;
    if (sample.type == basic_block_ack) {
        bitmap_detail = tr("%1 of %2 sequence positions have one or more fragment bits set; "
                           "%3 fragment bit(s) are set")
                .arg(set_positions)
                .arg(window_positions)
                .arg(bitmapSetBitCount(sample));
    } else {
        bitmap_detail = tr("%1 of %2 bitmap positions are set")
                .arg(set_positions)
                .arg(window_positions);
    }

    d_->details_label->setText(
                tr("Frame %1 · %2 BA · TA %3 → RA %4 · TID %5 · SSN %6 · "
                   "window upper bound %7 (exclusive) · %8. "
                   "Click a BA point to go to this frame.")
                .arg(sample.frame_number)
                .arg(blockAckTypeName(sample.type))
                .arg(d_->sessions.at(session_index).ta,
                     d_->sessions.at(session_index).ra)
                .arg(sample.tid)
                .arg(sample.starting_sequence)
                .arg(upper_bound)
                .arg(bitmap_detail));

    d_->anchor_graph->setSelection(
                QCPDataSelection(QCPDataRange(data_index, data_index + 1)));
    d_->plot->replot(QCustomPlot::rpQueuedReplot);
}

int WlanBlockAckGraphDialog::anchorIndexForPlottable(
        QCPAbstractPlottable *plottable, int data_index) const
{
    if (!plottable || data_index < 0) {
        return -1;
    }
    if (plottable == d_->anchor_graph) {
        return data_index < d_->anchor_sample_indexes.size() ? data_index : -1;
    }
    if (plottable == d_->window_upper_graph) {
        return data_index < d_->anchor_sample_indexes.size() ? data_index : -1;
    }
    if (plottable == d_->set_graph && data_index < d_->set_anchor_indexes.size()) {
        return d_->set_anchor_indexes.at(data_index);
    }
    if (plottable == d_->hole_graph && data_index < d_->hole_anchor_indexes.size()) {
        return d_->hole_anchor_indexes.at(data_index);
    }
    return -1;
}

void WlanBlockAckGraphDialog::stationPairChanged(int)
{
    int preferred_tid = -1;
    int previous_session = currentSessionIndex();
    if (previous_session >= 0) {
        preferred_tid = static_cast<int>(d_->sessions.at(previous_session).tid);
    }
    populateTids(-1, preferred_tid);
    drawSession();
}

void WlanBlockAckGraphDialog::tidChanged(int)
{
    drawSession();
}

void WlanBlockAckGraphDialog::bitmapHolesToggled(bool checked)
{
    d_->hole_graph->setVisible(checked);
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::plotClicked(QCPAbstractPlottable *plottable,
                                          int data_index, QMouseEvent *event)
{
    if (!event || event->button() != Qt::LeftButton) {
        return;
    }
    int anchor_index = anchorIndexForPlottable(plottable, data_index);
    if (anchor_index >= 0) {
        showSampleDetails(anchor_index);
        if (!file_closed_ && d_->selected_frame > 0) {
            emit goToPacket(static_cast<int>(d_->selected_frame));
        }
    }
}

void WlanBlockAckGraphDialog::zoomXAxis(bool in)
{
    double factor = d_->plot->axisRect()->rangeZoomFactor(Qt::Horizontal);
    if (!in && factor != 0.0) {
        factor = 1.0 / factor;
    }
    d_->plot->xAxis->scaleRange(factor, d_->plot->xAxis->range().center());
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::zoomYAxis(bool in)
{
    double factor = d_->plot->axisRect()->rangeZoomFactor(Qt::Vertical);
    if (!in && factor != 0.0) {
        factor = 1.0 / factor;
    }
    d_->plot->yAxis->scaleRange(factor, d_->plot->yAxis->range().center());
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::resetAxes()
{
    if (d_->anchor_graph->data()->isEmpty()) {
        d_->plot->xAxis->setRange(0.0, 1.0);
        d_->plot->yAxis->setRange(0.0, 1.0);
        d_->plot->replot();
        return;
    }

    bool have_x_range = false;
    QCPRange x_range = d_->anchor_graph->getKeyRange(have_x_range);
    if (!have_x_range) {
        x_range = QCPRange(0.0, 1.0);
        d_->plot->xAxis->setRange(x_range);
    } else if (!QCPRange::validRange(x_range)) {
        d_->plot->xAxis->setRange(x_range.center() - 0.5, x_range.center() + 0.5);
    } else {
        d_->plot->xAxis->setRange(x_range);
        d_->plot->xAxis->scaleRange(1.08, x_range.center());
    }

    bool have_y_range = false;
    QCPRange y_range;
    const QVector<QCPGraph *> value_graphs = {
        d_->anchor_graph, d_->window_upper_graph, d_->set_graph,
        d_->show_holes->isChecked() ? d_->hole_graph : nullptr
    };
    for (QCPGraph *graph : value_graphs) {
        if (!graph) {
            continue;
        }
        bool graph_has_range = false;
        QCPRange graph_range = graph->getValueRange(graph_has_range);
        if (graph_has_range) {
            if (have_y_range) {
                y_range.expand(graph_range);
            } else {
                y_range = graph_range;
                have_y_range = true;
            }
        }
    }
    if (!have_y_range) {
        y_range = QCPRange(0.0, 1.0);
    }
    if (!QCPRange::validRange(y_range) || y_range.size() < 1.0) {
        d_->plot->yAxis->setRange(y_range.center() - 1.0, y_range.center() + 1.0);
    } else {
        d_->plot->yAxis->setRange(y_range);
        d_->plot->yAxis->scaleRange(1.12, y_range.center());
    }
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::saveGraph()
{
    QDir path(mainApp->openDialogInitialDir());
    QString pdf_filter = tr("Portable Document Format (*.pdf)");
    QString png_filter = tr("Portable Network Graphics (*.png)");
    QString bmp_filter = tr("Windows Bitmap (*.bmp)");
    QString jpeg_filter = tr("JPEG File Interchange Format (*.jpeg *.jpg)");
    QString selected_filter;
    QString filters = QStringLiteral("%1;;%2;;%3;;%4")
            .arg(pdf_filter, png_filter, bmp_filter, jpeg_filter);
    QString file_name = WiresharkFileDialog::getSaveFileName(
                this, mainApp->windowTitleString(tr("Save Graph As…")),
                path.canonicalPath(), filters, &selected_filter);
    if (file_name.isEmpty()) {
        return;
    }

    bool saved = false;
    if (selected_filter == pdf_filter) {
        saved = d_->plot->savePdf(file_name);
    } else if (selected_filter == png_filter) {
        saved = d_->plot->savePng(file_name);
    } else if (selected_filter == bmp_filter) {
        saved = d_->plot->saveBmp(file_name);
    } else if (selected_filter == jpeg_filter) {
        saved = d_->plot->saveJpg(file_name);
    }
    if (saved) {
        mainApp->setLastOpenDirFromFilename(file_name);
    }
}

void WlanBlockAckGraphDialog::captureFileClosing()
{
    removeTapListeners();
    d_->station_pair_combo->setEnabled(false);
    d_->tid_combo->setEnabled(false);
    WiresharkDialog::captureFileClosing();
}
