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

#include <wsutil/str_util.h>

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
constexpr int sequence_modulus = 4096;
constexpr int sequence_half_range = sequence_modulus / 2;

class SequenceNumberAxisTicker : public QCPAxisTickerFixed
{
protected:
    QString getTickLabel(double tick, const QLocale &, QChar, int) override
    {
        qint64 sequence = qRound64(tick) % sequence_modulus;
        if (sequence < 0) {
            sequence += sequence_modulus;
        }
        return QString::number(sequence);
    }
};

static QString timeDeltaLabel(double seconds)
{
    QString elapsed = gchar_free_to_qstring(
                format_units(nullptr, seconds, FORMAT_SIZE_UNIT_SECONDS,
                             FORMAT_SIZE_PREFIX_SI, 3));
    return QObject::tr("Δt %1").arg(elapsed);
}

using FieldIds = QVector<int>;
using FieldInfos = QVector<const field_info *>;

struct BaSample {
    uint32_t frame_number = 0;
    double relative_time = 0.0;
    bool is_request = false;
    uint32_t type = 0;
    uint32_t tid = 0;
    uint32_t starting_sequence = 0;
    QByteArray bitmap;
};

struct MpduSample {
    uint32_t frame_number = 0;
    double relative_time = 0.0;
    uint32_t sequence = 0;
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

static QString etherFieldValue(epan_dissect *edt, const FieldIds &hf_ids)
{
    for (const field_info *field : fieldInfos(edt, hf_ids)) {
        if (field->hfinfo->type != FT_ETHER ||
            fvalue_get_bytes_size(field->value) != FT_ETHER_LEN) {
            continue;
        }
        const uint8_t *data = static_cast<const uint8_t *>(
                    fvalue_get_bytes_data(field->value));
        if (data) {
            return QString::fromLatin1(
                        QByteArray(reinterpret_cast<const char *>(data),
                                   FT_ETHER_LEN).toHex(':'));
        }
    }
    return QString();
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

static int unwrapSequence(uint32_t sequence, uint32_t previous_sequence,
                          int previous_unwrapped)
{
    int delta = (static_cast<int>(sequence) - static_cast<int>(previous_sequence) +
                 sequence_half_range) & (sequence_modulus - 1);
    delta -= sequence_half_range;
    return previous_unwrapped + delta;
}

static bool isQosDataSubtype(uint32_t subtype)
{
    return subtype >= 0x0028 && subtype <= 0x002b;
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
        hf_type_subtype(fieldIdsByName("wlan.fc.type_subtype")),
        hf_ba_type(fieldIdsByName("wlan.ba.control.ba_type")),
        hf_single_tid(fieldIdsByName("wlan.ba.basic.tidinfo")),
        hf_multi_tid(fieldIdsByName("wlan.bar.mtid.tidinfo.value")),
        hf_starting_sequence(fieldIdsByName("wlan.fixed.ssc.sequence")),
        hf_bitmap(fieldIdsByName("wlan.ba.bm")),
        hf_qos_tid(fieldIdsByName("wlan.qos.tid")),
        hf_mpdu_sequence(fieldIdsByName("wlan.seq")),
        hf_ta(fieldIdsByName("wlan.ta")),
        hf_ra(fieldIdsByName("wlan.ra"))
    {
    }

    FieldIds hf_type_subtype;
    FieldIds hf_ba_type;
    FieldIds hf_single_tid;
    FieldIds hf_multi_tid;
    FieldIds hf_starting_sequence;
    FieldIds hf_bitmap;
    FieldIds hf_qos_tid;
    FieldIds hf_mpdu_sequence;
    FieldIds hf_ta;
    FieldIds hf_ra;

    QVector<BaSession> sessions;
    QVector<BaStaPair> sta_pairs;
    QHash<QString, int> session_indexes;
    QHash<QString, QVector<MpduSample>> captured_mpdus;
    QVector<int> anchor_sample_indexes;
    QVector<int> anchor_unwrapped_sequences;
    QVector<int> request_sample_indexes;
    QVector<int> request_unwrapped_sequences;
    QVector<int> mpdu_unwrapped_sequences;
    QVector<int> set_anchor_indexes;
    QVector<int> hole_anchor_indexes;
    QVector<QCPItemText *> ssn_labels;
    QVector<QCPItemText *> time_delta_labels;

    QComboBox *station_pair_combo = nullptr;
    QComboBox *tid_combo = nullptr;
    QCheckBox *show_ssn_labels = nullptr;
    QCheckBox *show_time_deltas = nullptr;
    QCheckBox *show_ack_gaps = nullptr;
    QCheckBox *show_mpdus = nullptr;
    QCheckBox *show_holes = nullptr;
    QCustomPlot *plot = nullptr;
    QLabel *details_label = nullptr;
    QLabel *status_label = nullptr;
    QDialogButtonBox *button_box = nullptr;
    QCPGraph *anchor_graph = nullptr;
    QCPGraph *request_graph = nullptr;
    QCPGraph *window_upper_graph = nullptr;
    QCPGraph *set_graph = nullptr;
    QCPGraph *hole_graph = nullptr;
    QCPGraph *advance_span_graph = nullptr;
    QCPGraph *mpdu_graph = nullptr;

    uint32_t initially_selected_frame = 0;
    uint32_t selected_frame = 0;
    int total_ba_frames = 0;
    int total_bar_frames = 0;
    int unsupported_ba_frames = 0;
    int unsupported_bar_frames = 0;
    int malformed_ba_frames = 0;
    int malformed_bar_frames = 0;
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
    QLabel *station_pair_label = new QLabel(tr("BA pair (TA → RA):"), this);
    d_->station_pair_combo = new QComboBox(this);
    d_->station_pair_combo->setObjectName(QStringLiteral("stationPairComboBox"));
    d_->station_pair_combo->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    d_->station_pair_combo->setToolTip(
                tr("The pair direction follows Block Ack responses. Matching Block Ack "
                   "Requests travel in the reverse direction."));
    station_pair_label->setBuddy(d_->station_pair_combo);
    QLabel *tid_label = new QLabel(tr("TID:"), this);
    d_->tid_combo = new QComboBox(this);
    d_->tid_combo->setObjectName(QStringLiteral("tidComboBox"));
    d_->tid_combo->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    tid_label->setBuddy(d_->tid_combo);
    d_->show_ssn_labels = new QCheckBox(tr("Show SSN labels"), this);
    d_->show_ssn_labels->setObjectName(QStringLiteral("showSsnLabelsCheckBox"));
    d_->show_ssn_labels->setChecked(true);
    d_->show_ssn_labels->setToolTip(
                tr("Show the numeric starting sequence number (SSN) below each blue BA point. "
                   "The blue BA starting-sequence trace remains visible."));
    d_->show_time_deltas = new QCheckBox(tr("Show BA time deltas"), this);
    d_->show_time_deltas->setObjectName(QStringLiteral("showBaTimeDeltasCheckBox"));
    d_->show_time_deltas->setChecked(false);
    d_->show_time_deltas->setToolTip(
                tr("Show the elapsed time since the previous BA in the selected STA pair and "
                   "TID above the blue segment between them. The first BA has no time delta."));
    d_->show_ack_gaps = new QCheckBox(tr("Show BA ACK gaps"), this);
    d_->show_ack_gaps->setObjectName(QStringLiteral("showBaAckGapsCheckBox"));
    d_->show_ack_gaps->setChecked(true);
    d_->show_ack_gaps->setToolTip(
                tr("Show sequence numbers for which no acknowledgment was observed in a BA "
                   "before a later BA SSN advanced past them. This uses Block Ack evidence "
                   "only and does not prove that an MPDU was transmitted or lost."));
    d_->show_mpdus = new QCheckBox(tr("Show captured MPDUs"), this);
    d_->show_mpdus->setObjectName(QStringLiteral("showMpduSequencesCheckBox"));
    d_->show_mpdus->setChecked(true);
    d_->show_mpdus->setToolTip(
                tr("Show captured QoS Data MPDU sequence numbers in the reverse data direction "
                   "(BA RA → BA TA) for the selected TID. Each captured A-MPDU subframe is "
                   "plotted separately, including retransmissions."));
    d_->show_holes = new QCheckBox(tr("Show bitmap holes"), this);
    d_->show_holes->setObjectName(QStringLiteral("showBitmapHolesCheckBox"));
    d_->show_holes->setChecked(true);
    d_->show_holes->setToolTip(tr("Show zero bitmap positions before the highest set position. "
                                  "A zero does not prove that a frame was transmitted or lost."));
    session_layout->addWidget(station_pair_label);
    session_layout->addWidget(d_->station_pair_combo, 1);
    session_layout->addWidget(tid_label);
    session_layout->addWidget(d_->tid_combo);
    session_layout->addWidget(d_->show_ssn_labels);
    session_layout->addWidget(d_->show_time_deltas);
    session_layout->addWidget(d_->show_ack_gaps);
    session_layout->addWidget(d_->show_mpdus);
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
                   "X / Shift+X and Y / Shift+Y. When enabled, gray dots mark sequence numbers "
                   "for which no acknowledgment was observed before a later BA SSN advanced "
                   "past them. Purple diamonds show captured reverse-direction QoS Data MPDUs; "
                   "they do not affect the Block Ack analysis."));
    d_->plot->addLayer(QStringLiteral("baSsnLabels"), d_->plot->layer(QStringLiteral("main")),
                       QCustomPlot::limBelow);
    d_->plot->addLayer(QStringLiteral("baTimeDeltaLabels"),
                       d_->plot->layer(QStringLiteral("main")), QCustomPlot::limBelow);
    d_->plot->xAxis->setLabel(tr("Time"));
    d_->plot->xAxis->setTicker(QSharedPointer<QCPAxisTickerSi>(
                                   new QCPAxisTickerSi(FORMAT_SIZE_UNIT_SECONDS)));
    d_->plot->xAxis->setNumberPrecision(9);
    d_->plot->yAxis->setLabel(tr("Sequence number (12-bit; labels modulo 4096)"));
    QSharedPointer<QCPAxisTickerFixed> sequence_ticker(new SequenceNumberAxisTicker);
    sequence_ticker->setTickStep(1.0);
    sequence_ticker->setScaleStrategy(QCPAxisTickerFixed::ssMultiples);
    d_->plot->yAxis->setTicker(sequence_ticker);
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

    d_->request_graph = d_->plot->addGraph();
    d_->request_graph->setObjectName(QStringLiteral("barStartingSequenceGraph"));
    d_->request_graph->setName(tr("BAR starting sequence"));
    d_->request_graph->setLineStyle(QCPGraph::lsNone);
    d_->request_graph->setPen(QPen(QColor(tango_plum_4), 1.5));
    d_->request_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssTriangle, QColor(tango_plum_5),
                                QColor(Qt::white), 8));
    d_->request_graph->setSelectable(QCP::stSingleData);

    d_->mpdu_graph = d_->plot->addGraph();
    d_->mpdu_graph->setObjectName(QStringLiteral("capturedMpduSequenceGraph"));
    d_->mpdu_graph->setName(tr("Captured QoS Data MPDU sequence"));
    d_->mpdu_graph->setLineStyle(QCPGraph::lsNone);
    d_->mpdu_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssDiamond, QColor(tango_plum_5),
                                QColor(Qt::white), 6));
    d_->mpdu_graph->setSelectable(QCP::stSingleData);

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

    d_->advance_span_graph = d_->plot->addGraph();
    d_->advance_span_graph->setObjectName(QStringLiteral("baSsnAdvanceSpanGraph"));
    d_->advance_span_graph->setName(tr("No BA ACK before SSN advance"));
    d_->advance_span_graph->setLineStyle(QCPGraph::lsNone);
    d_->advance_span_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssDisc,
                                QColor(tango_aluminium_6),
                                QColor(tango_aluminium_4), 7));
    d_->advance_span_graph->setSelectable(QCP::stNone);

    d_->details_label = new QLabel(
                tr("Block Ack responses drive the acknowledgment analysis. Matching captured "
                   "QoS Data MPDUs can be displayed separately, but capture presence does not "
                   "prove reception by the destination. Bitmap zeros mean “not acknowledged "
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
    connect(d_->show_ssn_labels, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::ssnLabelsToggled);
    connect(d_->show_time_deltas, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::timeDeltasToggled);
    connect(d_->show_ack_gaps, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::ackGapsToggled);
    connect(d_->show_mpdus, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::mpdusToggled);
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
    dialog->d_->captured_mpdus.clear();
    dialog->d_->total_ba_frames = 0;
    dialog->d_->total_bar_frames = 0;
    dialog->d_->unsupported_ba_frames = 0;
    dialog->d_->unsupported_bar_frames = 0;
    dialog->d_->malformed_ba_frames = 0;
    dialog->d_->malformed_bar_frames = 0;
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
    QVector<uint32_t> subtypes = unsignedFieldValues(edt, d->hf_type_subtype);
    bool is_request = subtypes.contains(0x0018);
    bool is_response = subtypes.contains(0x0019);
    bool is_qos_data = std::any_of(subtypes.cbegin(), subtypes.cend(), isQosDataSubtype);

    if (is_qos_data && !is_request && !is_response) {
        QVector<uint32_t> tids = unsignedFieldValues(edt, d->hf_qos_tid);
        QVector<uint32_t> sequences = unsignedFieldValues(edt, d->hf_mpdu_sequence);
        QString data_ta = etherFieldValue(edt, d->hf_ta);
        QString data_ra = etherFieldValue(edt, d->hf_ra);
        if (data_ta.isEmpty() || data_ra.isEmpty() ||
            tids.size() != 1 || sequences.size() != 1) {
            return TAP_PACKET_DONT_REDRAW;
        }

        MpduSample sample;
        sample.frame_number = pinfo->num;
        sample.relative_time = nstime_to_sec(&pinfo->rel_ts);
        sample.sequence = sequences.first() & 0x0fff;

        // QoS Data travels opposite to its Block Ack response. Normalize the
        // key to the BA TA → RA direction used by the session picker.
        QString key = sessionKey(data_ra, data_ta, tids.first() & 0x0f);
        d->captured_mpdus[key].append(sample);
        return TAP_PACKET_REDRAW;
    }

    if (is_request == is_response) {
        return TAP_PACKET_DONT_REDRAW;
    }

    int &total_frames = is_request ? d->total_bar_frames : d->total_ba_frames;
    int &unsupported_frames = is_request
            ? d->unsupported_bar_frames : d->unsupported_ba_frames;
    int &malformed_frames = is_request
            ? d->malformed_bar_frames : d->malformed_ba_frames;
    total_frames++;

    if (!pinfo->dl_src.data || pinfo->dl_src.len != 6 ||
        !pinfo->dl_dst.data || pinfo->dl_dst.len != 6) {
        malformed_frames++;
        return TAP_PACKET_DONT_REDRAW;
    }

    QVector<uint32_t> types = unsignedFieldValues(edt, d->hf_ba_type);
    QVector<uint32_t> starting_sequences = unsignedFieldValues(edt, d->hf_starting_sequence);
    if (types.isEmpty()) {
        malformed_frames++;
        return TAP_PACKET_DONT_REDRAW;
    }

    uint32_t type = types.first();
    if (type != basic_block_ack && type != extended_compressed_block_ack &&
        type != compressed_block_ack && type != multi_tid_block_ack) {
        // GCR adds a group address to its session identity, and Multi-STA
        // normally supplies only an AID for each entry. Including either in a
        // TA/RA/TID-only graph would merge distinct peers or groups.
        unsupported_frames++;
        return TAP_PACKET_DONT_REDRAW;
    }

    QVector<uint32_t> tids = type == multi_tid_block_ack
            ? unsignedFieldValues(edt, d->hf_multi_tid)
            : unsignedFieldValues(edt, d->hf_single_tid);
    if (type != multi_tid_block_ack && tids.size() > 1) {
        tids.resize(1);
    }

    QVector<QByteArray> bitmaps;
    if (!is_request) {
        bitmaps = byteFieldValues(edt, d->hf_bitmap);
    }
    if (tids.isEmpty() || tids.size() != starting_sequences.size() ||
        (!is_request && tids.size() != bitmaps.size())) {
        malformed_frames++;
        return TAP_PACKET_DONT_REDRAW;
    }

    QString ta = address_to_qstring(&pinfo->dl_src);
    QString ra = address_to_qstring(&pinfo->dl_dst);
    for (int i = 0; i < tids.size(); i++) {
        BaSample sample;
        sample.frame_number = pinfo->num;
        sample.relative_time = nstime_to_sec(&pinfo->rel_ts);
        sample.is_request = is_request;
        sample.type = type;
        sample.tid = tids.at(i);
        sample.starting_sequence = starting_sequences.at(i) & 0x0fff;

        if (!is_request) {
            sample.bitmap = bitmaps.at(i);
            // Basic BA contains 64 16-bit fragment bitmaps. Other supported
            // BA formats contain one bit per sequence number.
            if (!validBitmapSize(type, static_cast<int>(sample.bitmap.size()))) {
                malformed_frames++;
                continue;
            }
        }

        // A BAR travels from the data originator to the BA recipient. Store it
        // in the reverse, BA-response direction so the request and response
        // appear in the same TA/RA/TID session.
        QString session_ta = is_request ? ra : ta;
        QString session_ra = is_request ? ta : ra;
        QString key = sessionKey(session_ta, session_ra, sample.tid);
        int session_index = d->session_indexes.value(key, -1);
        if (session_index < 0) {
            BaSession session;
            session.ta = session_ta;
            session.ra = session_ra;
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
    // tree. QoS Data subtypes 0x28 through 0x2b carry the per-TID MPDU sequence
    // numbers plotted alongside Block Ack Requests and responses.
    static const char tap_filter[] =
            "(wlan.fc.type_subtype == 0x0018 || "
            "wlan.fc.type_subtype == 0x0019 || "
            "wlan.fc.type_subtype == 0x0028 || "
            "wlan.fc.type_subtype == 0x0029 || "
            "wlan.fc.type_subtype == 0x002a || "
            "wlan.fc.type_subtype == 0x002b) && "
            "(wlan.ta || wlan.ra || wlan.ba.control.ba_type || "
            "wlan.ba.basic.tidinfo || wlan.bar.mtid.tidinfo.value || "
            "wlan.fixed.ssc.sequence || wlan.ba.bm || wlan.qos.tid || wlan.seq)";

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

    for (auto it = d_->captured_mpdus.begin(); it != d_->captured_mpdus.end(); ++it) {
        std::stable_sort(it.value().begin(), it.value().end(),
                         [](const MpduSample &left, const MpduSample &right) {
            if (left.relative_time != right.relative_time) {
                return left.relative_time < right.relative_time;
            }
            return left.frame_number < right.frame_number;
        });
    }

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
        if (selected_session < 0 && d_->initially_selected_frame > 0) {
            const auto mpdu_it = d_->captured_mpdus.constFind(
                        sessionKey(session.ta, session.ra, session.tid));
            if (mpdu_it != d_->captured_mpdus.cend() &&
                std::any_of(mpdu_it->cbegin(), mpdu_it->cend(), [this](const MpduSample &sample) {
                    return sample.frame_number == d_->initially_selected_frame;
                })) {
                selected_session = session_index;
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
        int response_count = 0;
        for (const BaSample &sample : session.samples) {
            response_count += sample.is_request ? 0 : 1;
        }
        int request_count = static_cast<int>(session.samples.size()) - response_count;
        d_->tid_combo->addItem(
                    tr("TID %1 · %2 BA(s) · %3 BAR(s)")
                    .arg(session.tid)
                    .arg(response_count)
                    .arg(request_count), session_index);
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
    QCPLayer *ssn_label_layer = d_->plot->layer(QStringLiteral("baSsnLabels"));
    if (ssn_label_layer) {
        ssn_label_layer->setVisible(d_->show_ssn_labels->isChecked());
    }
    clearTimeDeltaLabels();
    for (QCPItemText *label : d_->ssn_labels) {
        d_->plot->removeItem(label);
    }
    d_->ssn_labels.clear();
    d_->anchor_graph->data()->clear();
    d_->anchor_graph->setSelection(QCPDataSelection());
    d_->request_graph->data()->clear();
    d_->request_graph->setSelection(QCPDataSelection());
    d_->mpdu_graph->data()->clear();
    d_->mpdu_graph->setSelection(QCPDataSelection());
    d_->window_upper_graph->data()->clear();
    d_->set_graph->data()->clear();
    d_->hole_graph->data()->clear();
    d_->advance_span_graph->data()->clear();
    d_->anchor_sample_indexes.clear();
    d_->anchor_unwrapped_sequences.clear();
    d_->request_sample_indexes.clear();
    d_->request_unwrapped_sequences.clear();
    d_->mpdu_unwrapped_sequences.clear();
    d_->set_anchor_indexes.clear();
    d_->hole_anchor_indexes.clear();
    d_->selected_frame = 0;

    int session_index = currentSessionIndex();
    if (session_index < 0 || session_index >= d_->sessions.size()) {
        d_->show_ssn_labels->setEnabled(false);
        d_->show_time_deltas->setEnabled(false);
        d_->show_ack_gaps->setEnabled(false);
        d_->show_mpdus->setEnabled(false);
        d_->show_holes->setEnabled(false);
        d_->button_box->button(QDialogButtonBox::Save)->setEnabled(false);
        d_->button_box->button(QDialogButtonBox::Reset)->setEnabled(false);
        d_->details_label->setText(
                    tr("Block Ack responses drive the acknowledgment analysis. Matching "
                       "captured QoS Data MPDUs can be displayed separately, but capture "
                       "presence does not prove reception by the destination. Bitmap zeros "
                       "mean “not acknowledged in this BA”; they do not prove transmission "
                       "or packet loss."));
        d_->status_label->setText(
                    tr("No supported Block Ack sessions found · %1 BA / %2 BAR examined · "
                       "%3/%4 unsupported BA/BAR · %5/%6 malformed BA/BAR")
                    .arg(d_->total_ba_frames)
                    .arg(d_->total_bar_frames)
                    .arg(d_->unsupported_ba_frames)
                    .arg(d_->unsupported_bar_frames)
                    .arg(d_->malformed_ba_frames)
                    .arg(d_->malformed_bar_frames));
        d_->plot->xAxis->setRange(0.0, 1.0);
        d_->plot->yAxis->setRange(0.0, 1.0);
        d_->plot->replot();
        return;
    }

    const BaSession &session = d_->sessions.at(session_index);
    int response_count = 0;
    for (const BaSample &sample : session.samples) {
        response_count += sample.is_request ? 0 : 1;
    }
    int request_count = static_cast<int>(session.samples.size()) - response_count;
    bool have_responses = response_count > 0;
    const auto mpdu_it = d_->captured_mpdus.constFind(
                sessionKey(session.ta, session.ra, session.tid));
    const QVector<MpduSample> *mpdus = mpdu_it == d_->captured_mpdus.cend()
            ? nullptr : &mpdu_it.value();
    int mpdu_count = mpdus ? static_cast<int>(mpdus->size()) : 0;
    d_->show_ssn_labels->setEnabled(have_responses);
    d_->show_time_deltas->setEnabled(have_responses);
    d_->show_ack_gaps->setEnabled(have_responses);
    d_->show_mpdus->setEnabled(mpdu_count > 0);
    d_->show_holes->setEnabled(have_responses);
    d_->button_box->button(QDialogButtonBox::Save)->setEnabled(true);
    d_->button_box->button(QDialogButtonBox::Reset)->setEnabled(true);
    QVector<double> anchor_times;
    QVector<double> anchor_sequences;
    QVector<double> request_times;
    QVector<double> request_sequences;
    QVector<double> mpdu_times;
    QVector<double> mpdu_sequences;
    QVector<double> window_upper_times;
    QVector<double> window_upper_sequences;
    QVector<double> set_times;
    QVector<double> set_sequences;
    QVector<double> hole_times;
    QVector<double> hole_sequences;
    QVector<double> advance_span_times;
    QVector<double> advance_span_sequences;
    // Exclusive frontier: the first trailing sequence without an observed BA ACK.
    int next_sequence_after_highest_ack = 0;
    bool have_ack_frontier = false;
    // BARs are plotted near the latest BA but must not affect BA unwrapping or analysis.
    uint32_t previous_ba_sequence = 0;
    int previous_ba_unwrapped = 0;
    bool have_previous_ba = false;

    for (int sample_index = 0; sample_index < session.samples.size(); sample_index++) {
        const BaSample &sample = session.samples.at(sample_index);
        int unwrapped = static_cast<int>(sample.starting_sequence);
        if (have_previous_ba) {
            unwrapped = unwrapSequence(sample.starting_sequence, previous_ba_sequence,
                                       previous_ba_unwrapped);
        }

        if (sample.is_request) {
            request_times.append(sample.relative_time);
            request_sequences.append(unwrapped);
            d_->request_sample_indexes.append(sample_index);
            d_->request_unwrapped_sequences.append(unwrapped);
            continue;
        }

        bool ba_ssn_moved_backward = have_previous_ba &&
                unwrapped < previous_ba_unwrapped;
        previous_ba_sequence = sample.starting_sequence;
        previous_ba_unwrapped = unwrapped;
        have_previous_ba = true;

        anchor_times.append(sample.relative_time);
        anchor_sequences.append(unwrapped);
        d_->anchor_sample_indexes.append(sample_index);
        d_->anchor_unwrapped_sequences.append(unwrapped);
        int anchor_index = static_cast<int>(d_->anchor_sample_indexes.size()) - 1;

        int positions = bitmapPositionCount(sample);
        // The same TA/RA/TID can start a new BA epoch later in the capture.
        // A backward window wholly below the ACK frontier cannot extend the
        // current epoch, so start a new frontier. Modulo wrap has already been
        // unwrapped forward and does not satisfy this condition.
        if (have_ack_frontier && ba_ssn_moved_backward &&
            unwrapped + positions <= next_sequence_after_highest_ack) {
            next_sequence_after_highest_ack = 0;
            have_ack_frontier = false;
        }
        window_upper_times.append(sample.relative_time);
        window_upper_sequences.append(unwrapped + positions);

        if (have_ack_frontier && unwrapped > next_sequence_after_highest_ack) {
            for (int sequence = next_sequence_after_highest_ack;
                 sequence < unwrapped; sequence++) {
                advance_span_times.append(sample.relative_time);
                advance_span_sequences.append(sequence);
            }
        }

        QCPItemText *ssn_label = new QCPItemText(d_->plot);
        ssn_label->setObjectName(
                    QStringLiteral("baSsnLabel_%1").arg(sample.frame_number));
        ssn_label->position->setAxes(d_->plot->xAxis, d_->plot->yAxis);
        ssn_label->position->setCoords(sample.relative_time, unwrapped);
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

        int sample_next_sequence_after_highest_ack = highest_set >= 0
                ? unwrapped + highest_set + 1 : unwrapped;
        if (have_ack_frontier) {
            next_sequence_after_highest_ack = std::max(
                        next_sequence_after_highest_ack,
                        sample_next_sequence_after_highest_ack);
        } else {
            next_sequence_after_highest_ack = sample_next_sequence_after_highest_ack;
            have_ack_frontier = true;
        }

        for (int position = 0; position <= highest_set; position++) {
            if (bitmapPositionSet(sample, position)) {
                set_times.append(sample.relative_time);
                set_sequences.append(unwrapped + position);
                d_->set_anchor_indexes.append(anchor_index);
            } else {
                hole_times.append(sample.relative_time);
                hole_sequences.append(unwrapped + position);
                d_->hole_anchor_indexes.append(anchor_index);
            }
        }
    }

    if (mpdus) {
        int latest_anchor = -1;
        uint32_t previous_mpdu_sequence = 0;
        int previous_mpdu_unwrapped = 0;
        bool have_previous_mpdu = false;
        for (const MpduSample &mpdu : *mpdus) {
            int unwrapped = static_cast<int>(mpdu.sequence);
            if (!d_->anchor_sample_indexes.isEmpty()) {
                // Use the latest preceding BA so a later BA epoch cannot move
                // an earlier MPDU to another modulo-4096 layer. Before the
                // first BA, use that first response as the reference instead.
                while (latest_anchor + 1 < d_->anchor_sample_indexes.size()) {
                    const BaSample &next_ba = session.samples.at(
                                d_->anchor_sample_indexes.at(latest_anchor + 1));
                    bool next_ba_is_after = next_ba.relative_time > mpdu.relative_time ||
                            (next_ba.relative_time == mpdu.relative_time &&
                             next_ba.frame_number > mpdu.frame_number);
                    if (next_ba_is_after) {
                        break;
                    }
                    latest_anchor++;
                }
                int reference_anchor = latest_anchor >= 0 ? latest_anchor : 0;
                const BaSample &reference_ba = session.samples.at(
                            d_->anchor_sample_indexes.at(reference_anchor));
                unwrapped = unwrapSequence(
                            mpdu.sequence, reference_ba.starting_sequence,
                            d_->anchor_unwrapped_sequences.at(reference_anchor));
            } else if (have_previous_mpdu) {
                unwrapped = unwrapSequence(mpdu.sequence, previous_mpdu_sequence,
                                           previous_mpdu_unwrapped);
            }

            mpdu_times.append(mpdu.relative_time);
            mpdu_sequences.append(unwrapped);
            d_->mpdu_unwrapped_sequences.append(unwrapped);
            previous_mpdu_sequence = mpdu.sequence;
            previous_mpdu_unwrapped = unwrapped;
            have_previous_mpdu = true;
        }
    }

    d_->anchor_graph->setData(anchor_times, anchor_sequences, true);
    d_->request_graph->setData(request_times, request_sequences, true);
    d_->mpdu_graph->setData(mpdu_times, mpdu_sequences, true);
    d_->window_upper_graph->setData(window_upper_times, window_upper_sequences, true);
    d_->set_graph->setData(set_times, set_sequences, true);
    d_->hole_graph->setData(hole_times, hole_sequences, true);
    d_->advance_span_graph->setData(advance_span_times, advance_span_sequences, true);
    d_->advance_span_graph->setVisible(d_->show_ack_gaps->isChecked());
    d_->mpdu_graph->setVisible(d_->show_mpdus->isChecked());
    d_->hole_graph->setVisible(d_->show_holes->isChecked());
    if (d_->show_time_deltas->isChecked()) {
        drawTimeDeltaLabels();
    }

    d_->status_label->setText(
                tr("%1 session(s) · %2 BA / %3 BAR in this session · "
                   "%4 captured QoS Data MPDU(s) · %5 bitmap-set position(s) · "
                   "%6 bitmap hole(s) · %7 no-BA-ACK-before-SSN-advance dot(s) · "
                   "%8/%9 unsupported BA/BAR · %10/%11 malformed BA/BAR")
                .arg(d_->sessions.size())
                .arg(response_count)
                .arg(request_count)
                .arg(mpdu_count)
                .arg(set_times.size())
                .arg(hole_times.size())
                .arg(advance_span_times.size())
                .arg(d_->unsupported_ba_frames)
                .arg(d_->unsupported_bar_frames)
                .arg(d_->malformed_ba_frames)
                .arg(d_->malformed_bar_frames));

    bool details_shown = false;
    for (int anchor_index = 0;
         anchor_index < d_->anchor_sample_indexes.size(); anchor_index++) {
        int sample_index = d_->anchor_sample_indexes.at(anchor_index);
        if (session.samples.at(sample_index).frame_number == preferred_frame) {
            showSampleDetails(anchor_index);
            details_shown = true;
            break;
        }
    }
    if (!details_shown) {
        for (int request_index = 0;
             request_index < d_->request_sample_indexes.size(); request_index++) {
            int sample_index = d_->request_sample_indexes.at(request_index);
            if (session.samples.at(sample_index).frame_number == preferred_frame) {
                showRequestDetails(request_index);
                details_shown = true;
                break;
            }
        }
    }
    if (!details_shown && mpdus) {
        for (int mpdu_index = 0; mpdu_index < mpdus->size(); mpdu_index++) {
            if (mpdus->at(mpdu_index).frame_number == preferred_frame) {
                showMpduDetails(mpdu_index);
                details_shown = true;
                break;
            }
        }
    }
    if (!details_shown && !d_->anchor_sample_indexes.isEmpty()) {
        showSampleDetails(0);
    } else if (!details_shown && !d_->request_sample_indexes.isEmpty()) {
        showRequestDetails(0);
    }
    resetAxes();
}

void WlanBlockAckGraphDialog::clearTimeDeltaLabels()
{
    for (QCPItemText *label : d_->time_delta_labels) {
        d_->plot->removeItem(label);
    }
    d_->time_delta_labels.clear();
}

void WlanBlockAckGraphDialog::drawTimeDeltaLabels()
{
    int session_index = currentSessionIndex();
    if (session_index < 0 || session_index >= d_->sessions.size()) {
        return;
    }

    const QVector<BaSample> &samples = d_->sessions.at(session_index).samples;
    qsizetype sample_count = std::min(d_->anchor_sample_indexes.size(),
                                      d_->anchor_unwrapped_sequences.size());
    for (qsizetype anchor_index = 1; anchor_index < sample_count; anchor_index++) {
        const BaSample &previous = samples.at(
                    d_->anchor_sample_indexes.at(anchor_index - 1));
        const BaSample &sample = samples.at(d_->anchor_sample_indexes.at(anchor_index));
        double delta = sample.relative_time - previous.relative_time;

        QCPItemText *delta_label = new QCPItemText(d_->plot);
        delta_label->setObjectName(
                    QStringLiteral("baTimeDeltaLabel_%1").arg(sample.frame_number));
        delta_label->position->setAxes(d_->plot->xAxis, d_->plot->yAxis);
        delta_label->position->setCoords(previous.relative_time + delta / 2.0,
                                         d_->anchor_unwrapped_sequences.at(anchor_index - 1));
        delta_label->setText(timeDeltaLabel(delta));
        delta_label->setPositionAlignment(Qt::AlignHCenter | Qt::AlignBottom);
        delta_label->setTextAlignment(Qt::AlignHCenter);
        delta_label->setPadding(QMargins(0, 0, 0, 5));
        QFont label_font = d_->plot->font();
        label_font.setPointSize(8);
        delta_label->setFont(label_font);
        delta_label->setColor(QColor(tango_plum_5));
        delta_label->setPen(Qt::NoPen);
        delta_label->setBrush(Qt::NoBrush);
        delta_label->setSelectable(false);
        delta_label->setClipAxisRect(d_->plot->axisRect());
        delta_label->setClipToAxisRect(true);
        delta_label->setLayer(QStringLiteral("baTimeDeltaLabels"));
        d_->time_delta_labels.append(delta_label);
    }
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
    int unwrapped_upper_bound = d_->anchor_unwrapped_sequences.at(data_index) +
            window_positions;
    uint32_t upper_bound = (sample.starting_sequence + window_positions) & 0x0fff;
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
                tr("Frame %1 · %2 BA · TA %3 → RA %4 · TID %5 · SSN %6 "
                   "(unwrapped %7) · window upper bound %8 (unwrapped %9, exclusive) · "
                   "%10. Click a BA point to go to this frame.")
                .arg(sample.frame_number)
                .arg(blockAckTypeName(sample.type))
                .arg(d_->sessions.at(session_index).ta,
                     d_->sessions.at(session_index).ra)
                .arg(sample.tid)
                .arg(sample.starting_sequence)
                .arg(d_->anchor_unwrapped_sequences.at(data_index))
                .arg(upper_bound)
                .arg(unwrapped_upper_bound)
                .arg(bitmap_detail));

    d_->request_graph->setSelection(QCPDataSelection());
    d_->mpdu_graph->setSelection(QCPDataSelection());
    d_->anchor_graph->setSelection(
                QCPDataSelection(QCPDataRange(data_index, data_index + 1)));
    d_->plot->replot(QCustomPlot::rpQueuedReplot);
}

void WlanBlockAckGraphDialog::showRequestDetails(int data_index)
{
    int session_index = currentSessionIndex();
    if (session_index < 0 || session_index >= d_->sessions.size() ||
        data_index < 0 || data_index >= d_->request_sample_indexes.size() ||
        data_index >= d_->request_unwrapped_sequences.size()) {
        return;
    }

    int sample_index = d_->request_sample_indexes.at(data_index);
    const BaSession &session = d_->sessions.at(session_index);
    const BaSample &sample = session.samples.at(sample_index);
    if (!sample.is_request) {
        return;
    }
    d_->selected_frame = sample.frame_number;

    d_->details_label->setText(
                tr("Frame %1 · %2 BAR · TA %3 → RA %4 · TID %5 · SSN %6 "
                   "(unwrapped %7). Click a BAR point to go to this frame.")
                .arg(sample.frame_number)
                .arg(blockAckTypeName(sample.type))
                .arg(session.ra, session.ta)
                .arg(sample.tid)
                .arg(sample.starting_sequence)
                .arg(d_->request_unwrapped_sequences.at(data_index)));

    d_->anchor_graph->setSelection(QCPDataSelection());
    d_->mpdu_graph->setSelection(QCPDataSelection());
    d_->request_graph->setSelection(
                QCPDataSelection(QCPDataRange(data_index, data_index + 1)));
    d_->plot->replot(QCustomPlot::rpQueuedReplot);
}

void WlanBlockAckGraphDialog::showMpduDetails(int data_index)
{
    int session_index = currentSessionIndex();
    if (session_index < 0 || session_index >= d_->sessions.size() ||
        data_index < 0 || data_index >= d_->mpdu_unwrapped_sequences.size()) {
        return;
    }

    const BaSession &session = d_->sessions.at(session_index);
    const auto mpdu_it = d_->captured_mpdus.constFind(
                sessionKey(session.ta, session.ra, session.tid));
    if (mpdu_it == d_->captured_mpdus.cend() || data_index >= mpdu_it->size()) {
        return;
    }

    const MpduSample &mpdu = mpdu_it->at(data_index);
    d_->selected_frame = mpdu.frame_number;
    d_->details_label->setText(
                tr("Frame %1 · Captured QoS Data MPDU · TA %2 → RA %3 · TID %4 · "
                   "sequence %5 (unwrapped %6). Capture presence does not prove reception "
                   "by the destination. Click an MPDU point to go to this frame.")
                .arg(mpdu.frame_number)
                .arg(session.ra, session.ta)
                .arg(session.tid)
                .arg(mpdu.sequence)
                .arg(d_->mpdu_unwrapped_sequences.at(data_index)));

    d_->anchor_graph->setSelection(QCPDataSelection());
    d_->request_graph->setSelection(QCPDataSelection());
    d_->mpdu_graph->setSelection(
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

void WlanBlockAckGraphDialog::ssnLabelsToggled(bool checked)
{
    QCPLayer *label_layer = d_->plot->layer(QStringLiteral("baSsnLabels"));
    if (label_layer) {
        label_layer->setVisible(checked);
    }
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::timeDeltasToggled(bool checked)
{
    clearTimeDeltaLabels();
    if (checked) {
        drawTimeDeltaLabels();
    }
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::ackGapsToggled(bool checked)
{
    d_->advance_span_graph->setVisible(checked);
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::mpdusToggled(bool checked)
{
    d_->mpdu_graph->setVisible(checked);
    d_->plot->replot();
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

    bool sample_selected = false;
    if (plottable == d_->mpdu_graph &&
        data_index >= 0 && data_index < d_->mpdu_unwrapped_sequences.size()) {
        showMpduDetails(data_index);
        sample_selected = true;
    } else if (plottable == d_->request_graph &&
        data_index >= 0 && data_index < d_->request_sample_indexes.size()) {
        showRequestDetails(data_index);
        sample_selected = true;
    } else {
        int anchor_index = anchorIndexForPlottable(plottable, data_index);
        if (anchor_index >= 0) {
            showSampleDetails(anchor_index);
            sample_selected = true;
        }
    }
    if (sample_selected && !file_closed_ && d_->selected_frame > 0) {
        emit goToPacket(static_cast<int>(d_->selected_frame));
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
    bool mpdus_visible = d_->show_mpdus->isChecked() &&
            !d_->mpdu_graph->data()->isEmpty();
    if (d_->anchor_graph->data()->isEmpty() &&
        d_->request_graph->data()->isEmpty() && !mpdus_visible) {
        d_->plot->xAxis->setRange(0.0, 1.0);
        d_->plot->yAxis->setRange(0.0, 1.0);
        d_->plot->replot();
        return;
    }

    bool have_x_range = false;
    QCPRange x_range;
    const QVector<QCPGraph *> time_graphs = {
        d_->anchor_graph, d_->request_graph,
        mpdus_visible ? d_->mpdu_graph : nullptr
    };
    for (QCPGraph *graph : time_graphs) {
        if (!graph) {
            continue;
        }
        bool graph_has_range = false;
        QCPRange graph_range = graph->getKeyRange(graph_has_range);
        if (graph_has_range) {
            if (have_x_range) {
                x_range.expand(graph_range);
            } else {
                x_range = graph_range;
                have_x_range = true;
            }
        }
    }
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
        d_->anchor_graph, d_->request_graph, d_->window_upper_graph, d_->set_graph,
        d_->show_holes->isChecked() ? d_->hole_graph : nullptr,
        d_->show_ack_gaps->isChecked() ? d_->advance_span_graph : nullptr,
        mpdus_visible ? d_->mpdu_graph : nullptr
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
