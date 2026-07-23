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
#include <QButtonGroup>
#include <QCheckBox>
#include <QComboBox>
#include <QCursor>
#include <QDialogButtonBox>
#include <QDir>
#include <QHash>
#include <QHBoxLayout>
#include <QLabel>
#include <QMouseEvent>
#include <QPushButton>
#include <QRadioButton>
#include <QRubberBand>
#include <QSet>
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
constexpr uint32_t block_ack_action_category = 3;
constexpr uint32_t add_block_ack_request = 0;
constexpr uint32_t add_block_ack_response = 1;
constexpr uint32_t delete_block_ack = 2;
constexpr double management_retry_dedup_seconds = 1.0;
constexpr int sequence_modulus = 4096;
constexpr int sequence_half_range = sequence_modulus / 2;
constexpr int min_zoom_pixels = 20;
constexpr int min_agreement_event_label_spacing = 90;

static int wrappedSequence(qint64 sequence)
{
    sequence %= sequence_modulus;
    return static_cast<int>(sequence < 0 ? sequence + sequence_modulus : sequence);
}

class SequenceNumberAxisTicker : public QCPAxisTickerFixed
{
protected:
    QString getTickLabel(double tick, const QLocale &, QChar, int) override
    {
        return QString::number(wrappedSequence(qRound64(tick)));
    }
};

static QString durationLabel(double seconds)
{
    return gchar_free_to_qstring(
                format_units(nullptr, seconds, FORMAT_SIZE_UNIT_SECONDS,
                             FORMAT_SIZE_PREFIX_SI, 3));
}

static QString timeDeltaLabel(double seconds)
{
    return QObject::tr("Δt %1").arg(durationLabel(seconds));
}

static QRectF zoomRanges(QCustomPlot *plot, const QRect &zoom_rect)
{
    if (!plot) {
        return QRectF();
    }

    QRect normalized_rect = zoom_rect.normalized();
    if (normalized_rect.width() < min_zoom_pixels &&
        normalized_rect.height() < min_zoom_pixels) {
        return QRectF();
    }

    QRect selected_rect = plot->axisRect()->rect().intersected(normalized_rect);
    if (selected_rect.width() <= 0 || selected_rect.height() <= 0) {
        return QRectF();
    }

    double x1 = plot->xAxis->pixelToCoord(selected_rect.left());
    double x2 = plot->xAxis->pixelToCoord(selected_rect.right());
    double y1 = plot->yAxis->pixelToCoord(selected_rect.bottom());
    double y2 = plot->yAxis->pixelToCoord(selected_rect.top());
    return QRectF(QPointF(x1, y1), QPointF(x2, y2)).normalized();
}

static int graphPointCountInRange(const QCPGraph *graph,
                                  const QCPRange &key_range,
                                  const QCPRange &value_range)
{
    if (!graph) {
        return 0;
    }

    QSharedPointer<QCPGraphDataContainer> data = graph->data();
    int count = 0;
    auto begin = data->findBegin(key_range.lower, false);
    auto end = data->findEnd(key_range.upper, false);
    for (auto it = begin; it != end; ++it) {
        if (value_range.contains(it->value)) {
            count++;
        }
    }
    return count;
}

using FieldIds = QVector<int>;
using FieldInfos = QVector<const field_info *>;

struct BaSample {
    uint32_t frame_number = 0;
    double relative_time = 0.0;
    bool is_request = false;
    bool explicit_fcs_error = false;
    uint32_t type = 0;
    uint32_t tid = 0;
    uint32_t starting_sequence = 0;
    QByteArray bitmap;
};

enum class AgreementEventType {
    AddbaRequest,
    AddbaResponseAccepted,
    AddbaResponseRejected,
    Delba,
    InferredEpochReset
};

struct AgreementEvent {
    uint32_t frame_number = 0;
    double relative_time = 0.0;
    AgreementEventType type = AgreementEventType::AddbaRequest;
    uint32_t dialog_token = 0;
    uint32_t status_code = 0;
    uint32_t reason_code = 0;
    uint32_t starting_sequence = 0;
    QString status_text;
    QString reason_text;
    bool has_dialog_token = false;
    bool has_status_code = false;
    bool has_reason_code = false;
    bool has_starting_sequence = false;
    bool sender_is_originator = false;
    bool explicit_fcs_error = false;
};

static bool agreementEventStartsAnalysis(AgreementEventType type)
{
    return type == AgreementEventType::AddbaResponseAccepted;
}

static bool agreementEventEndsAnalysis(AgreementEventType type)
{
    return type == AgreementEventType::Delba;
}

static bool agreementEventResetsAnalysis(AgreementEventType type)
{
    return agreementEventStartsAnalysis(type) || agreementEventEndsAnalysis(type) ||
            type == AgreementEventType::InferredEpochReset;
}

static QString agreementEventLabel(const AgreementEvent &event)
{
    switch (event.type) {
    case AgreementEventType::AddbaRequest:
        return QObject::tr("ADDBA Req");
    case AgreementEventType::AddbaResponseAccepted:
        return QObject::tr("ADDBA OK");
    case AgreementEventType::AddbaResponseRejected:
        return QObject::tr("ADDBA Reject");
    case AgreementEventType::Delba:
        return QObject::tr("DELBA");
    case AgreementEventType::InferredEpochReset:
        return QObject::tr("SSN reset");
    }
    return QString();
}

static QColor agreementEventColor(const AgreementEvent &event)
{
    if (event.explicit_fcs_error) {
        return QColor(tango_aluminium_5);
    }

    switch (event.type) {
    case AgreementEventType::AddbaRequest:
        return QColor(tango_plum_4);
    case AgreementEventType::AddbaResponseAccepted:
        return QColor(tango_chameleon_5);
    case AgreementEventType::AddbaResponseRejected:
        return QColor(tango_orange_5);
    case AgreementEventType::Delba:
        return QColor(tango_scarlet_red_5);
    case AgreementEventType::InferredEpochReset:
        return QColor(tango_aluminium_5);
    }
    return QColor(tango_aluminium_5);
}

static Qt::PenStyle agreementEventPenStyle(AgreementEventType type)
{
    switch (type) {
    case AgreementEventType::AddbaRequest:
        return Qt::DashLine;
    case AgreementEventType::AddbaResponseAccepted:
        return Qt::SolidLine;
    case AgreementEventType::AddbaResponseRejected:
    case AgreementEventType::Delba:
        return Qt::DashDotLine;
    case AgreementEventType::InferredEpochReset:
        return Qt::DotLine;
    }
    return Qt::SolidLine;
}

struct MpduSample {
    uint32_t frame_number = 0;
    double relative_time = 0.0;
    uint32_t sequence = 0;
    bool retry = false;
};

enum class PersistentHoleOutcome {
    Acknowledged,
    PassedBySsn,
    WindowInterrupted,
    AgreementStarted,
    AgreementEnded,
    EpochReset,
    Active
};

struct PersistentHoleTrack {
    uint32_t first_frame_number = 0;
    double first_relative_time = 0.0;
    int last_zero_anchor_index = -1;
    uint32_t last_zero_frame_number = 0;
    double last_zero_relative_time = 0.0;
    int ba_count = 0;
};

struct PersistentHoleSpan {
    int unwrapped_sequence = 0;
    int endpoint_anchor_index = -1;
    uint32_t first_frame_number = 0;
    double first_relative_time = 0.0;
    double endpoint_relative_time = 0.0;
    uint32_t terminal_frame_number = 0;
    int ba_count = 0;
    PersistentHoleOutcome outcome = PersistentHoleOutcome::Active;
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
    int ba_count = 0;
};

static int baResponseCount(const BaSession &session)
{
    int count = 0;
    for (const BaSample &sample : session.samples) {
        count += sample.is_request ? 0 : 1;
    }
    return count;
}

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

static QString singleFieldDisplayValue(epan_dissect *edt, const FieldIds &hf_ids)
{
    FieldInfos fields = fieldInfos(edt, hf_ids);
    if (fields.size() != 1) {
        return QString();
    }

    char display_label[ITEM_LABEL_LENGTH];
    int length = proto_item_fill_display_label(
                fields.first(), display_label, ITEM_LABEL_LENGTH);
    return length > 0 ? QString::fromUtf8(display_label, length) : QString();
}

static QVector<uint32_t> unsignedFieldValues(epan_dissect *edt, const FieldIds &hf_ids)
{
    QVector<uint32_t> values;
    for (const field_info *field : fieldInfos(edt, hf_ids)) {
        values.append(fvalue_get_uinteger(field->value));
    }
    return values;
}

static QVector<bool> booleanFieldValues(epan_dissect *edt, const FieldIds &hf_ids)
{
    QVector<bool> values;
    for (const field_info *field : fieldInfos(edt, hf_ids)) {
        if (field->hfinfo->type == FT_BOOLEAN) {
            values.append(fvalue_get_uinteger64(field->value) != 0);
        }
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
        hf_action_category(fieldIdsByName("wlan.fixed.category_code")),
        hf_action_code(fieldIdsByName("wlan.fixed.action_code")),
        hf_addba_tid(fieldIdsByName("wlan.fixed.baparams.tid")),
        hf_delba_tid(fieldIdsByName("wlan.fixed.delba.param.tid")),
        hf_delba_initiator(fieldIdsByName("wlan.fixed.delba.param.initiator")),
        hf_status_code(fieldIdsByName("wlan.fixed.status_code")),
        hf_retry(fieldIdsByName("wlan.fc.retry")),
        hf_dialog_token(fieldIdsByName("wlan.fixed.dialog_token")),
        hf_reason_code(fieldIdsByName("wlan.fixed.reason_code")),
        hf_fcs_status(fieldIdsByName("wlan.fcs.status")),
        hf_radiotap_bad_fcs(fieldIdsByName("radiotap.flags.badfcs")),
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
    FieldIds hf_action_category;
    FieldIds hf_action_code;
    FieldIds hf_addba_tid;
    FieldIds hf_delba_tid;
    FieldIds hf_delba_initiator;
    FieldIds hf_status_code;
    FieldIds hf_retry;
    FieldIds hf_dialog_token;
    FieldIds hf_reason_code;
    FieldIds hf_fcs_status;
    FieldIds hf_radiotap_bad_fcs;
    FieldIds hf_qos_tid;
    FieldIds hf_mpdu_sequence;
    FieldIds hf_ta;
    FieldIds hf_ra;

    QVector<BaSession> sessions;
    QVector<BaStaPair> sta_pairs;
    QHash<QString, int> session_indexes;
    QHash<QString, QVector<AgreementEvent>> agreement_events;
    QHash<QString, double> agreement_retry_times;
    QHash<QString, uint32_t> agreement_retry_frames;
    QHash<uint32_t, uint32_t> agreement_retry_frame_aliases;
    QHash<uint32_t, QString> agreement_frame_session_keys;
    QHash<QString, QVector<MpduSample>> captured_mpdus;
    QVector<AgreementEvent> displayed_agreement_events;
    QVector<int> anchor_sample_indexes;
    QVector<int> anchor_unwrapped_sequences;
    QVector<int> request_sample_indexes;
    QVector<int> request_unwrapped_sequences;
    QVector<int> mpdu_unwrapped_sequences;
    QVector<int> mpdu_sample_indexes;
    QVector<int> retry_mpdu_sample_indexes;
    QVector<int> set_anchor_indexes;
    QVector<int> previously_set_zero_anchor_indexes;
    QVector<int> hole_anchor_indexes;
    QVector<int> bad_fcs_anchor_indexes;
    QVector<int> bad_fcs_set_anchor_indexes;
    QVector<int> bad_fcs_zero_anchor_indexes;
    QVector<PersistentHoleSpan> persistent_hole_spans;
    QVector<QCPItemText *> ssn_labels;
    QVector<QCPItemText *> time_delta_labels;
    QVector<QCPItemLine *> agreement_event_lines;
    QVector<QCPItemText *> agreement_event_labels;

    QComboBox *station_pair_combo = nullptr;
    QComboBox *tid_combo = nullptr;
    QRadioButton *mouse_drag_radio = nullptr;
    QRadioButton *mouse_zoom_radio = nullptr;
    QCheckBox *show_ssn_labels = nullptr;
    QCheckBox *show_time_deltas = nullptr;
    QCheckBox *show_ack_gaps = nullptr;
    QCheckBox *show_mpdus = nullptr;
    QCheckBox *show_persistent_holes = nullptr;
    QCheckBox *show_bitmap_set = nullptr;
    QCheckBox *show_holes = nullptr;
    QCheckBox *show_agreement_events = nullptr;
    QCustomPlot *plot = nullptr;
    QLabel *details_label = nullptr;
    QLabel *status_label = nullptr;
    QDialogButtonBox *button_box = nullptr;
    QCPGraph *anchor_graph = nullptr;
    QCPGraph *request_graph = nullptr;
    QCPGraph *window_upper_graph = nullptr;
    QCPGraph *set_graph = nullptr;
    QCPGraph *previously_set_zero_graph = nullptr;
    QCPGraph *hole_graph = nullptr;
    QCPGraph *persistent_hole_graph = nullptr;
    QCPErrorBars *persistent_hole_error_bars = nullptr;
    QCPGraph *advance_span_graph = nullptr;
    QCPGraph *bad_fcs_anchor_graph = nullptr;
    QCPGraph *bad_fcs_window_upper_graph = nullptr;
    QCPGraph *bad_fcs_set_graph = nullptr;
    QCPGraph *bad_fcs_zero_graph = nullptr;
    QCPGraph *mpdu_graph = nullptr;
    QCPGraph *retry_mpdu_graph = nullptr;
    QRubberBand *zoom_rubber_band = nullptr;
    QPoint zoom_origin;

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
                   "Requests travel in the reverse direction. Pairs are sorted by the "
                   "received BA count summed across all TIDs."));
    station_pair_label->setBuddy(d_->station_pair_combo);
    QLabel *tid_label = new QLabel(tr("TID:"), this);
    d_->tid_combo = new QComboBox(this);
    d_->tid_combo->setObjectName(QStringLiteral("tidComboBox"));
    d_->tid_combo->setSizeAdjustPolicy(QComboBox::AdjustToContents);
    d_->tid_combo->setToolTip(
                tr("TIDs are sorted by received BA count, highest first."));
    tid_label->setBuddy(d_->tid_combo);
    d_->mouse_drag_radio = new QRadioButton(tr("Drag"), this);
    d_->mouse_drag_radio->setObjectName(QStringLiteral("mouseDragRadioButton"));
    d_->mouse_drag_radio->setToolTip(
                tr("Drag the plot to pan, and click plotted points for packet details."));
    d_->mouse_zoom_radio = new QRadioButton(tr("Zoom"), this);
    d_->mouse_zoom_radio->setObjectName(QStringLiteral("mouseZoomRadioButton"));
    d_->mouse_zoom_radio->setToolTip(
                tr("Drag a rectangle over the plot to zoom both axes to that area."));
    QButtonGroup *mouse_mode_group = new QButtonGroup(this);
    mouse_mode_group->addButton(d_->mouse_drag_radio);
    mouse_mode_group->addButton(d_->mouse_zoom_radio);
    d_->mouse_drag_radio->setChecked(true);
    d_->show_ssn_labels = new QCheckBox(tr("Show SSN labels"), this);
    d_->show_ssn_labels->setObjectName(QStringLiteral("showSsnLabelsCheckBox"));
    d_->show_ssn_labels->setChecked(false);
    d_->show_ssn_labels->setToolTip(
                tr("Show the starting sequence number (SSN) and the number of set bitmap "
                   "bits in parentheses below each blue BA point. The blue BA "
                   "starting-sequence trace remains visible."));
    d_->show_time_deltas = new QCheckBox(tr("Show BA time deltas"), this);
    d_->show_time_deltas->setObjectName(QStringLiteral("showBaTimeDeltasCheckBox"));
    d_->show_time_deltas->setChecked(false);
    d_->show_time_deltas->setToolTip(
                tr("Show the elapsed time since the previous BA in the selected STA pair and "
                   "TID above the blue segment between them. The first BA has no time delta."));
    d_->show_ack_gaps = new QCheckBox(tr("Show BA ACK gaps"), this);
    d_->show_ack_gaps->setObjectName(QStringLiteral("showBaAckGapsCheckBox"));
    d_->show_ack_gaps->setChecked(false);
    d_->show_ack_gaps->setToolTip(
                tr("Show sequence numbers for which no acknowledgment was observed in a BA "
                   "before a later BA SSN advanced past them. This uses Block Ack evidence "
                   "only and does not prove that an MPDU was transmitted or lost."));
    d_->show_mpdus = new QCheckBox(tr("Show captured MPDUs"), this);
    d_->show_mpdus->setObjectName(QStringLiteral("showMpduSequencesCheckBox"));
    d_->show_mpdus->setChecked(false);
    d_->show_mpdus->setToolTip(
                tr("Show captured QoS Data MPDU sequence numbers in the reverse data direction "
                   "(BA RA → BA TA) for the selected TID. Each captured A-MPDU subframe is "
                   "plotted separately. Filled gold diamonds have the Retry bit clear; "
                   "hollow orange diamonds have the Retry bit set."));
    d_->show_persistent_holes = new QCheckBox(tr("Show persistent-hole aging"), this);
    d_->show_persistent_holes->setObjectName(
                QStringLiteral("showPersistentHoleAgingCheckBox"));
    d_->show_persistent_holes->setChecked(false);
    d_->show_persistent_holes->setToolTip(
                tr("Show lifetimes of sequence numbers reported unacknowledged by two or more "
                   "consecutive Block Ack responses. This uses BA evidence only and does not "
                   "prove that an MPDU was transmitted or lost."));
    d_->show_bitmap_set = new QCheckBox(tr("Show bitmap set"), this);
    d_->show_bitmap_set->setObjectName(QStringLiteral("showBitmapSetCheckBox"));
    d_->show_bitmap_set->setChecked(true);
    d_->show_bitmap_set->setToolTip(
                tr("Show dots for set positions in each Block Ack bitmap. They are normally "
                   "green and gray for a BA with an explicit FCS error."));
    d_->show_holes = new QCheckBox(tr("Show bitmap holes"), this);
    d_->show_holes->setObjectName(QStringLiteral("showBitmapHolesCheckBox"));
    d_->show_holes->setChecked(false);
    d_->show_holes->setToolTip(
                tr("Show zero bitmap positions before the highest set position. Green "
                   "crosses were set by an earlier BA in the same agreement; red crosses "
                   "have no earlier observed set. Either is gray for a BA with an explicit "
                   "FCS error. A zero does not prove that a frame was transmitted or lost."));
    d_->show_agreement_events = new QCheckBox(
                tr("Show ADDBA/DELBA events"), this);
    d_->show_agreement_events->setObjectName(
                QStringLiteral("showAgreementEventsCheckBox"));
    d_->show_agreement_events->setChecked(true);
    d_->show_agreement_events->setToolTip(
                tr("Show packet-linked vertical markers for ADDBA requests, accepted or "
                   "rejected ADDBA responses, and DELBA frames in the selected BA session. "
                   "Requests are purple/dashed, accepted responses green/solid, rejected "
                   "responses orange/dash-dot, and DELBA frames dark red/dash-dot. Any "
                   "event with an explicit FCS error is gray. "
                   "Matching management-frame retries are collapsed into one marker. "
                   "Successful responses and DELBA frames reset the agreement analysis. "
                   "Gray dotted markers identify an SSN epoch reset inferred from BA data "
                   "when no captured management boundary explains it."));
    session_layout->addWidget(station_pair_label);
    session_layout->addWidget(d_->station_pair_combo, 1);
    session_layout->addWidget(tid_label);
    session_layout->addWidget(d_->tid_combo);
    main_layout->addLayout(session_layout);

    d_->plot = new QCustomPlot(this);
    d_->plot->setObjectName(QStringLiteral("blockAckPlot"));
    d_->plot->setInteractions(QCP::iRangeDrag | QCP::iRangeZoom |
                              QCP::iSelectPlottables | QCP::iSelectItems);
    d_->plot->axisRect()->setRangeDrag(Qt::Horizontal | Qt::Vertical);
    d_->plot->axisRect()->setRangeZoom(Qt::Horizontal | Qt::Vertical);
    d_->plot->axisRect()->setRangeDragAxes(d_->plot->xAxis, d_->plot->yAxis);
    d_->plot->axisRect()->setRangeZoomAxes(d_->plot->xAxis, d_->plot->yAxis);
    d_->plot->setContextMenuPolicy(Qt::ActionsContextMenu);
    d_->plot->setFocusPolicy(Qt::StrongFocus);
    d_->plot->setToolTip(
                tr("In Drag mode, drag the plot to pan or drag directly over an axis to "
                   "change only that axis. In Zoom mode, drag a rectangle to zoom both axes. "
                   "Use the wheel over the plot to zoom both axes, or over an axis to zoom "
                   "only that axis. Shortcuts: Z toggles Drag/Zoom mode; X / Shift+X and "
                   "Y / Shift+Y zoom individual axes. When enabled, gray dots mark sequence "
                   "numbers for which no acknowledgment was observed before a later BA SSN "
                   "advanced "
                   "past them. Dark-red horizontal spans show persistent BA bitmap holes; click "
                   "a square endpoint for its lifetime and resolution details. Filled gold "
                   "diamonds show captured reverse-direction QoS Data MPDUs with the Retry "
                   "bit clear; hollow orange diamonds show those with the Retry bit set. "
                   "Captured MPDUs do not affect the Block Ack analysis. When bitmap holes "
                   "are enabled, green crosses mark "
                   "zeros for positions set by an earlier BA in the same agreement; red "
                   "crosses mark positions without an earlier observed set. BA points and "
                   "bitmap positions explicitly reported with an FCS error are overlaid "
                   "in gray. Vertical markers show ADDBA and DELBA events for the selected "
                   "session; click a marker for packet details. An SSN reset marker means "
                   "that a new analysis epoch was inferred without a captured agreement "
                   "boundary."));
    d_->plot->addLayer(QStringLiteral("baAgreementEvents"),
                       d_->plot->layer(QStringLiteral("main")), QCustomPlot::limBelow);
    d_->plot->addLayer(QStringLiteral("baAgreementEventLabels"),
                       d_->plot->layer(QStringLiteral("main")), QCustomPlot::limAbove);
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
    d_->mpdu_graph->setName(tr("Captured QoS Data MPDU (Retry clear)"));
    d_->mpdu_graph->setLineStyle(QCPGraph::lsNone);
    d_->mpdu_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssDiamond, QColor(tango_butter_6),
                                QColor(tango_butter_3), 7));
    d_->mpdu_graph->setSelectable(QCP::stSingleData);

    d_->retry_mpdu_graph = d_->plot->addGraph();
    d_->retry_mpdu_graph->setObjectName(
                QStringLiteral("capturedRetryMpduSequenceGraph"));
    d_->retry_mpdu_graph->setName(tr("Captured QoS Data MPDU (Retry set)"));
    d_->retry_mpdu_graph->setLineStyle(QCPGraph::lsNone);
    d_->retry_mpdu_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssDiamond,
                                QPen(QColor(tango_orange_5), 1.75),
                                QBrush(Qt::NoBrush), 9));
    d_->retry_mpdu_graph->setSelectable(QCP::stSingleData);

    d_->window_upper_graph = d_->plot->addGraph();
    d_->window_upper_graph->setObjectName(QStringLiteral("baWindowUpperBoundGraph"));
    d_->window_upper_graph->setName(tr("BA window upper bound (exclusive)"));
    d_->window_upper_graph->setLineStyle(QCPGraph::lsStepLeft);
    d_->window_upper_graph->setPen(QPen(QColor(tango_orange_4), 1.5));
    d_->window_upper_graph->setSelectable(QCP::stNone);

    d_->set_graph = d_->plot->addGraph();
    d_->set_graph->setObjectName(QStringLiteral("baBitmapSetGraph"));
    d_->set_graph->setName(tr("BA bitmap set"));
    d_->set_graph->setLineStyle(QCPGraph::lsNone);
    d_->set_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssDisc,
                                                    QColor(tango_chameleon_5), 5));
    d_->set_graph->setSelectable(QCP::stNone);

    d_->previously_set_zero_graph = d_->plot->addGraph();
    d_->previously_set_zero_graph->setObjectName(
                QStringLiteral("baPreviouslySetZeroGraph"));
    d_->previously_set_zero_graph->setName(
                tr("BA bitmap zero after prior set"));
    d_->previously_set_zero_graph->setLineStyle(QCPGraph::lsNone);
    d_->previously_set_zero_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssCross,
                                QColor(tango_chameleon_5), 7));
    d_->previously_set_zero_graph->setSelectable(QCP::stNone);

    d_->hole_graph = d_->plot->addGraph();
    d_->hole_graph->setName(tr("BA bitmap zero without prior set"));
    d_->hole_graph->setLineStyle(QCPGraph::lsNone);
    d_->hole_graph->setScatterStyle(QCPScatterStyle(QCPScatterStyle::ssCross,
                                                     QColor(tango_scarlet_red_3), 7));
    d_->hole_graph->setSelectable(QCP::stNone);

    d_->persistent_hole_graph = d_->plot->addGraph();
    d_->persistent_hole_graph->setObjectName(
                QStringLiteral("persistentBaHoleLifetimeGraph"));
    d_->persistent_hole_graph->setName(tr("Persistent BA hole lifetime"));
    d_->persistent_hole_graph->setLineStyle(QCPGraph::lsNone);
    d_->persistent_hole_graph->setPen(QPen(QColor(tango_scarlet_red_4), 1.5));
    d_->persistent_hole_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssSquare,
                                QColor(tango_scarlet_red_4), QColor(Qt::white), 7));
    d_->persistent_hole_graph->setSelectable(QCP::stSingleData);
    d_->persistent_hole_graph->setLayer(QStringLiteral("overlay"));

    d_->persistent_hole_error_bars = new QCPErrorBars(d_->plot->xAxis, d_->plot->yAxis);
    d_->persistent_hole_error_bars->setObjectName(
                QStringLiteral("persistentBaHoleLifetimeSpans"));
    d_->persistent_hole_error_bars->setErrorType(QCPErrorBars::etKeyError);
    d_->persistent_hole_error_bars->setPen(QPen(QColor(tango_scarlet_red_4), 1.5));
    d_->persistent_hole_error_bars->setSymbolGap(0.0);
    d_->persistent_hole_error_bars->setWhiskerWidth(6.0);
    d_->persistent_hole_error_bars->setSelectable(QCP::stNone);
    d_->persistent_hole_error_bars->removeFromLegend();
    d_->persistent_hole_error_bars->setDataPlottable(d_->persistent_hole_graph);

    d_->advance_span_graph = d_->plot->addGraph();
    d_->advance_span_graph->setObjectName(QStringLiteral("baSsnAdvanceSpanGraph"));
    d_->advance_span_graph->setName(tr("No BA ACK before SSN advance"));
    d_->advance_span_graph->setLineStyle(QCPGraph::lsNone);
    d_->advance_span_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssDisc,
                                QColor(tango_aluminium_6),
                                QColor(tango_aluminium_4), 7));
    d_->advance_span_graph->setSelectable(QCP::stNone);

    // Keep the normal traces intact, then cover the markers belonging to an
    // explicitly bad-FCS BA. A step segment spans multiple samples and retains
    // its semantic blue/orange color; the sample itself and its bitmap are gray.
    d_->bad_fcs_anchor_graph = d_->plot->addGraph();
    d_->bad_fcs_anchor_graph->setObjectName(
                QStringLiteral("badFcsBaStartingSequenceGraph"));
    d_->bad_fcs_anchor_graph->setName(tr("BA with explicit FCS error"));
    d_->bad_fcs_anchor_graph->setLineStyle(QCPGraph::lsNone);
    d_->bad_fcs_anchor_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssDisc,
                                QColor(tango_aluminium_5),
                                QColor(tango_aluminium_3), 9));
    d_->bad_fcs_anchor_graph->setSelectable(QCP::stSingleData);
    QCPSelectionDecorator *bad_fcs_selection = new QCPSelectionDecorator;
    bad_fcs_selection->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssDisc,
                                QColor(tango_aluminium_6),
                                QColor(tango_aluminium_3), 11),
                QCPScatterStyle::spPen | QCPScatterStyle::spBrush |
                QCPScatterStyle::spSize);
    d_->bad_fcs_anchor_graph->setSelectionDecorator(bad_fcs_selection);

    d_->bad_fcs_window_upper_graph = d_->plot->addGraph();
    d_->bad_fcs_window_upper_graph->setObjectName(
                QStringLiteral("badFcsBaWindowUpperBoundGraph"));
    d_->bad_fcs_window_upper_graph->setLineStyle(QCPGraph::lsNone);
    d_->bad_fcs_window_upper_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssDisc,
                                QColor(tango_aluminium_5), 7));
    d_->bad_fcs_window_upper_graph->setSelectable(QCP::stNone);
    d_->bad_fcs_window_upper_graph->removeFromLegend();

    d_->bad_fcs_set_graph = d_->plot->addGraph();
    d_->bad_fcs_set_graph->setObjectName(
                QStringLiteral("badFcsBaBitmapSetGraph"));
    d_->bad_fcs_set_graph->setLineStyle(QCPGraph::lsNone);
    d_->bad_fcs_set_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssDisc,
                                QColor(tango_aluminium_5), 7));
    d_->bad_fcs_set_graph->setSelectable(QCP::stNone);
    d_->bad_fcs_set_graph->removeFromLegend();

    d_->bad_fcs_zero_graph = d_->plot->addGraph();
    d_->bad_fcs_zero_graph->setObjectName(
                QStringLiteral("badFcsBaBitmapZeroGraph"));
    d_->bad_fcs_zero_graph->setLineStyle(QCPGraph::lsNone);
    d_->bad_fcs_zero_graph->setScatterStyle(
                QCPScatterStyle(QCPScatterStyle::ssCross,
                                QColor(tango_aluminium_5), 9));
    d_->bad_fcs_zero_graph->setSelectable(QCP::stNone);
    d_->bad_fcs_zero_graph->removeFromLegend();

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
    d_->status_label->setWordWrap(true);
    main_layout->addWidget(d_->status_label);

    QHBoxLayout *mouse_layout = new QHBoxLayout;
    mouse_layout->addWidget(new QLabel(tr("Mouse:"), this));
    mouse_layout->addWidget(d_->mouse_drag_radio);
    mouse_layout->addWidget(d_->mouse_zoom_radio);
    mouse_layout->addStretch(1);
    main_layout->addLayout(mouse_layout);

    QHBoxLayout *display_layout = new QHBoxLayout;
    display_layout->addWidget(d_->show_ssn_labels);
    display_layout->addWidget(d_->show_time_deltas);
    display_layout->addWidget(d_->show_ack_gaps);
    display_layout->addWidget(d_->show_mpdus);
    display_layout->addWidget(d_->show_persistent_holes);
    display_layout->addWidget(d_->show_bitmap_set);
    display_layout->addWidget(d_->show_holes);
    display_layout->addWidget(d_->show_agreement_events);
    display_layout->addStretch(1);
    main_layout->addLayout(display_layout);

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
    QAction *toggle_mouse_mode_action = new QAction(tr("Toggle Mouse Drag/Zoom Mode"), d_->plot);
    toggle_mouse_mode_action->setShortcut(QKeySequence(Qt::Key_Z));
    toggle_mouse_mode_action->setShortcutContext(Qt::WindowShortcut);
    d_->plot->addAction(toggle_mouse_mode_action);

    connect(d_->station_pair_combo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &WlanBlockAckGraphDialog::stationPairChanged);
    connect(d_->tid_combo, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, &WlanBlockAckGraphDialog::tidChanged);
    connect(d_->mouse_zoom_radio, &QRadioButton::toggled,
            this, &WlanBlockAckGraphDialog::mouseZoomToggled);
    connect(d_->show_ssn_labels, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::ssnLabelsToggled);
    connect(d_->show_time_deltas, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::timeDeltasToggled);
    connect(d_->show_ack_gaps, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::ackGapsToggled);
    connect(d_->show_mpdus, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::mpdusToggled);
    connect(d_->show_persistent_holes, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::persistentHolesToggled);
    connect(d_->show_bitmap_set, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::bitmapSetToggled);
    connect(d_->show_holes, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::bitmapHolesToggled);
    connect(d_->show_agreement_events, &QCheckBox::toggled,
            this, &WlanBlockAckGraphDialog::agreementEventsToggled);
    connect(d_->plot, &QCustomPlot::plottableClick,
            this, &WlanBlockAckGraphDialog::plotClicked);
    connect(d_->plot, &QCustomPlot::itemClick,
            this, &WlanBlockAckGraphDialog::plotItemClicked);
    connect(d_->plot, &QCustomPlot::mousePress,
            this, &WlanBlockAckGraphDialog::plotMousePressed);
    connect(d_->plot, &QCustomPlot::mouseMove,
            this, &WlanBlockAckGraphDialog::plotMouseMoved);
    connect(d_->plot, &QCustomPlot::mouseRelease,
            this, &WlanBlockAckGraphDialog::plotMouseReleased);
    connect(d_->plot, &QCustomPlot::afterReplot,
            this, &WlanBlockAckGraphDialog::updateGraphSummary);
    connect(d_->plot, &QCustomPlot::afterLayout,
            this, &WlanBlockAckGraphDialog::updateAgreementEventLabelVisibility);
    connect(zoom_in_x_action, &QAction::triggered,
            this, [this]() { zoomXAxis(true); });
    connect(zoom_out_x_action, &QAction::triggered,
            this, [this]() { zoomXAxis(false); });
    connect(zoom_in_y_action, &QAction::triggered,
            this, [this]() { zoomYAxis(true); });
    connect(zoom_out_y_action, &QAction::triggered,
            this, [this]() { zoomYAxis(false); });
    connect(toggle_mouse_mode_action, &QAction::triggered, this, [this]() {
        if (d_->mouse_zoom_radio->isChecked()) {
            d_->mouse_drag_radio->setChecked(true);
        } else {
            d_->mouse_zoom_radio->setChecked(true);
        }
    });
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

bool WlanBlockAckGraphDialog::canFollowPacket(epan_dissect *edt)
{
    if (!edt || !edt->tree ||
        !edt->pi.dl_src.data || edt->pi.dl_src.len != FT_ETHER_LEN ||
        !edt->pi.dl_dst.data || edt->pi.dl_dst.len != FT_ETHER_LEN) {
        return false;
    }

    QVector<uint32_t> subtypes = unsignedFieldValues(
                edt, fieldIdsByName("wlan.fc.type_subtype"));
    bool is_request = subtypes.contains(0x0018);
    bool is_response = subtypes.contains(0x0019);
    if (is_request == is_response) {
        return false;
    }

    QVector<uint32_t> types = unsignedFieldValues(
                edt, fieldIdsByName("wlan.ba.control.ba_type"));
    QVector<uint32_t> starting_sequences = unsignedFieldValues(
                edt, fieldIdsByName("wlan.fixed.ssc.sequence"));
    if (types.isEmpty()) {
        return false;
    }

    uint32_t type = types.first();
    if (type != basic_block_ack && type != extended_compressed_block_ack &&
        type != compressed_block_ack && type != multi_tid_block_ack) {
        return false;
    }

    QVector<uint32_t> tids = type == multi_tid_block_ack
            ? unsignedFieldValues(
                  edt, fieldIdsByName("wlan.bar.mtid.tidinfo.value"))
            : unsignedFieldValues(
                  edt, fieldIdsByName("wlan.ba.basic.tidinfo"));
    if (type != multi_tid_block_ack && tids.size() > 1) {
        tids.resize(1);
    }
    if (tids.isEmpty() || tids.size() != starting_sequences.size()) {
        return false;
    }
    if (is_request) {
        return true;
    }

    QVector<QByteArray> bitmaps = byteFieldValues(
                edt, fieldIdsByName("wlan.ba.bm"));
    if (tids.size() != bitmaps.size()) {
        return false;
    }
    for (const QByteArray &bitmap : bitmaps) {
        if (validBitmapSize(type, static_cast<int>(bitmap.size()))) {
            return true;
        }
    }
    return false;
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
    dialog->d_->agreement_events.clear();
    dialog->d_->agreement_retry_times.clear();
    dialog->d_->agreement_retry_frames.clear();
    dialog->d_->agreement_retry_frame_aliases.clear();
    dialog->d_->agreement_frame_session_keys.clear();
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
    bool explicit_fcs_error =
            booleanFieldValues(edt, d->hf_radiotap_bad_fcs).contains(true) ||
            unsignedFieldValues(edt, d->hf_fcs_status).contains(PROTO_CHECKSUM_E_BAD);

    QVector<uint32_t> action_categories = unsignedFieldValues(
                edt, d->hf_action_category);
    QVector<uint32_t> action_codes = unsignedFieldValues(edt, d->hf_action_code);
    if (action_categories.contains(block_ack_action_category) &&
        action_codes.size() == 1 &&
        (action_codes.first() == add_block_ack_request ||
         action_codes.first() == add_block_ack_response ||
         action_codes.first() == delete_block_ack)) {
        if (!pinfo->dl_src.data || pinfo->dl_src.len != 6 ||
            !pinfo->dl_dst.data || pinfo->dl_dst.len != 6) {
            return TAP_PACKET_DONT_REDRAW;
        }

        bool is_addba_request = action_codes.first() == add_block_ack_request;
        bool is_addba_response = action_codes.first() == add_block_ack_response;
        bool is_addba = is_addba_request || is_addba_response;
        QVector<uint32_t> tids = unsignedFieldValues(
                    edt, is_addba ? d->hf_addba_tid : d->hf_delba_tid);
        QVector<uint32_t> status_codes;
        QVector<bool> initiators;
        if (is_addba_response) {
            status_codes = unsignedFieldValues(edt, d->hf_status_code);
        } else if (!is_addba_request) {
            initiators = booleanFieldValues(edt, d->hf_delba_initiator);
        }
        if (tids.size() != 1 ||
            (is_addba_response && status_codes.size() != 1) ||
            (!is_addba && initiators.size() != 1)) {
            return TAP_PACKET_DONT_REDRAW;
        }

        QString sender = address_to_qstring(&pinfo->dl_src);
        QString receiver = address_to_qstring(&pinfo->dl_dst);
        // Normalize every agreement event to the BA-response direction. An
        // ADDBA Request travels from the data originator to the recipient, an
        // ADDBA Response travels back, and DELBA uses its Initiator bit to say
        // which endpoint sent it.
        bool sender_is_originator = !is_addba && initiators.first() != 0;
        QString session_ta;
        QString session_ra;
        if (is_addba_request || sender_is_originator) {
            session_ta = receiver;
            session_ra = sender;
        } else {
            session_ta = sender;
            session_ra = receiver;
        }
        QString key = sessionKey(session_ta, session_ra, tids.first() & 0x0f);
        d->agreement_frame_session_keys.insert(pinfo->num, key);
        QVector<uint32_t> management_sequences = unsignedFieldValues(
                    edt, d->hf_mpdu_sequence);
        QVector<bool> retries = booleanFieldValues(edt, d->hf_retry);
        QVector<uint32_t> dialog_tokens = unsignedFieldValues(
                    edt, d->hf_dialog_token);
        QVector<uint32_t> reason_codes = unsignedFieldValues(
                    edt, d->hf_reason_code);
        bool have_retry_signature = management_sequences.size() == 1 &&
                retries.size() == 1 &&
                (is_addba ? dialog_tokens.size() == 1
                          : reason_codes.size() == 1);
        double relative_time = nstime_to_sec(&pinfo->rel_ts);
        QString retry_key;
        if (have_retry_signature) {
            // Retries retain the transmitter's management sequence number and
            // action details. Refresh the last-seen time across a retry chain;
            // a gap beyond the short burst still lets eventual 12-bit sequence
            // reuse create a new boundary.
            uint32_t action_detail = is_addba
                    ? dialog_tokens.first() : reason_codes.first();
            retry_key = QStringLiteral("%1|%2|%3|%4|%5|%6|%7")
                    .arg(key)
                    .arg(action_codes.first())
                    .arg(sender)
                    .arg(management_sequences.first())
                    .arg(action_detail)
                    .arg(is_addba ? 0 : initiators.first())
                    .arg(is_addba_response
                         ? QString::number(status_codes.first())
                         : QStringLiteral("-"));
            auto previous_retry = d->agreement_retry_times.constFind(retry_key);
            bool duplicate_retry = retries.first() &&
                    previous_retry != d->agreement_retry_times.cend() &&
                    relative_time >= previous_retry.value() &&
                    relative_time - previous_retry.value() <=
                    management_retry_dedup_seconds;
            if (previous_retry == d->agreement_retry_times.cend() ||
                relative_time > previous_retry.value()) {
                d->agreement_retry_times.insert(retry_key, relative_time);
            }
            if (duplicate_retry) {
                uint32_t retained_frame = d->agreement_retry_frames.value(retry_key, 0);
                if (retained_frame > 0) {
                    d->agreement_retry_frame_aliases.insert(
                                pinfo->num, retained_frame);
                }
                return TAP_PACKET_DONT_REDRAW;
            }
        }

        AgreementEvent event;
        event.frame_number = pinfo->num;
        event.relative_time = relative_time;
        event.sender_is_originator = sender_is_originator;
        event.explicit_fcs_error = explicit_fcs_error;
        if (is_addba_request) {
            event.type = AgreementEventType::AddbaRequest;
        } else if (is_addba_response) {
            event.type = status_codes.first() == 0
                    ? AgreementEventType::AddbaResponseAccepted
                    : AgreementEventType::AddbaResponseRejected;
        } else {
            event.type = AgreementEventType::Delba;
        }
        if (dialog_tokens.size() == 1) {
            event.dialog_token = dialog_tokens.first();
            event.has_dialog_token = true;
        }
        if (status_codes.size() == 1) {
            event.status_code = status_codes.first();
            event.status_text = singleFieldDisplayValue(edt, d->hf_status_code);
            event.has_status_code = true;
        }
        if (reason_codes.size() == 1) {
            event.reason_code = reason_codes.first();
            event.reason_text = singleFieldDisplayValue(edt, d->hf_reason_code);
            event.has_reason_code = true;
        }
        QVector<uint32_t> starting_sequences = unsignedFieldValues(
                    edt, d->hf_starting_sequence);
        if (is_addba_request && starting_sequences.size() == 1) {
            event.starting_sequence = starting_sequences.first() & 0x0fff;
            event.has_starting_sequence = true;
        }
        d->agreement_events[key].append(event);
        if (have_retry_signature) {
            d->agreement_retry_frames.insert(retry_key, pinfo->num);
        }
        return TAP_PACKET_DONT_REDRAW;
    }

    if (is_qos_data && !is_request && !is_response) {
        QVector<uint32_t> tids = unsignedFieldValues(edt, d->hf_qos_tid);
        QVector<uint32_t> sequences = unsignedFieldValues(edt, d->hf_mpdu_sequence);
        QVector<bool> retries = booleanFieldValues(edt, d->hf_retry);
        QString data_ta = etherFieldValue(edt, d->hf_ta);
        QString data_ra = etherFieldValue(edt, d->hf_ra);
        if (data_ta.isEmpty() || data_ra.isEmpty() ||
            tids.size() != 1 || sequences.size() != 1 || retries.size() != 1) {
            return TAP_PACKET_DONT_REDRAW;
        }

        MpduSample sample;
        sample.frame_number = pinfo->num;
        sample.relative_time = nstime_to_sec(&pinfo->rel_ts);
        sample.sequence = sequences.first() & 0x0fff;
        sample.retry = retries.first();

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
        sample.explicit_fcs_error = explicit_fcs_error;
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
    // numbers plotted alongside Block Ack Requests and responses. ADDBA and
    // DELBA management actions are shown as session events; successful ADDBA
    // responses and DELBA frames delimit prior-set bitmap history.
    static const char tap_filter[] =
            "((wlan.fc.type_subtype == 0x0018 || "
            "wlan.fc.type_subtype == 0x0019 || "
            "wlan.fc.type_subtype == 0x0028 || "
            "wlan.fc.type_subtype == 0x0029 || "
            "wlan.fc.type_subtype == 0x002a || "
            "wlan.fc.type_subtype == 0x002b) || "
            "(wlan.fc.type_subtype == 0x000d && "
            "wlan.fixed.category_code == 3 && "
            "(wlan.fixed.action_code == 0 || wlan.fixed.action_code == 1 || "
            "wlan.fixed.action_code == 2))) && "
            "(wlan.ta || wlan.ra || wlan.ba.control.ba_type || "
            "wlan.ba.basic.tidinfo || wlan.bar.mtid.tidinfo.value || "
            "wlan.fixed.ssc.sequence || wlan.ba.bm || wlan.qos.tid || wlan.seq || "
            "wlan.fixed.category_code || wlan.fixed.action_code || "
            "wlan.fixed.baparams.tid || wlan.fixed.delba.param.tid || "
            "wlan.fixed.delba.param.initiator || wlan.fixed.status_code || "
            "wlan.fc.retry || wlan.fixed.dialog_token || wlan.fixed.reason_code || "
            "wlan.fcs.status || radiotap.flags.badfcs)";

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

    for (auto it = d_->agreement_events.begin(); it != d_->agreement_events.end(); ++it) {
        std::stable_sort(it.value().begin(), it.value().end(),
                         [](const AgreementEvent &left, const AgreementEvent &right) {
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
        if (selected_session < 0 && d_->initially_selected_frame > 0) {
            QString key = sessionKey(session.ta, session.ra, session.tid);
            if (d_->agreement_frame_session_keys.value(
                        d_->initially_selected_frame) == key) {
                selected_session = session_index;
            }
        }
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
        // A response sample is stored per TID, so the pair total is the sum
        // of the BA counts shown by all of its TID entries.
        d_->sta_pairs.last().ba_count += baResponseCount(session);
    }

    for (BaStaPair &pair : d_->sta_pairs) {
        std::stable_sort(pair.session_indexes.begin(), pair.session_indexes.end(),
                         [this](int left_index, int right_index) {
            const BaSession &left = d_->sessions.at(left_index);
            const BaSession &right = d_->sessions.at(right_index);
            int left_ba_count = baResponseCount(left);
            int right_ba_count = baResponseCount(right);
            if (left_ba_count != right_ba_count) {
                return left_ba_count > right_ba_count;
            }
            return left.tid < right.tid;
        });
    }

    std::stable_sort(d_->sta_pairs.begin(), d_->sta_pairs.end(),
                     [](const BaStaPair &left, const BaStaPair &right) {
        if (left.ba_count != right.ba_count) {
            return left.ba_count > right.ba_count;
        }
        if (left.ta != right.ta) {
            return left.ta < right.ta;
        }
        return left.ra < right.ra;
    });

    bool pair_signals_blocked = d_->station_pair_combo->blockSignals(true);
    bool tid_signals_blocked = d_->tid_combo->blockSignals(true);
    d_->station_pair_combo->clear();
    d_->tid_combo->clear();
    int selected_pair = -1;
    for (int pair_index = 0; pair_index < d_->sta_pairs.size(); pair_index++) {
        const BaStaPair &pair = d_->sta_pairs.at(pair_index);
        d_->station_pair_combo->addItem(
                    tr("%1 → %2 · %3 BA(s) · %n TID(s)", "",
                       static_cast<int>(pair.session_indexes.size()))
                    .arg(pair.ta, pair.ra)
                    .arg(pair.ba_count), pair_index);
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
        int response_count = baResponseCount(session);
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
    clearAgreementEventMarkers();
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
    d_->retry_mpdu_graph->data()->clear();
    d_->retry_mpdu_graph->setSelection(QCPDataSelection());
    d_->window_upper_graph->data()->clear();
    d_->set_graph->data()->clear();
    d_->previously_set_zero_graph->data()->clear();
    d_->hole_graph->data()->clear();
    d_->persistent_hole_graph->data()->clear();
    d_->persistent_hole_graph->setSelection(QCPDataSelection());
    d_->persistent_hole_error_bars->data()->clear();
    d_->advance_span_graph->data()->clear();
    d_->bad_fcs_anchor_graph->data()->clear();
    d_->bad_fcs_anchor_graph->setSelection(QCPDataSelection());
    d_->bad_fcs_window_upper_graph->data()->clear();
    d_->bad_fcs_set_graph->data()->clear();
    d_->bad_fcs_zero_graph->data()->clear();
    d_->anchor_sample_indexes.clear();
    d_->anchor_unwrapped_sequences.clear();
    d_->request_sample_indexes.clear();
    d_->request_unwrapped_sequences.clear();
    d_->mpdu_unwrapped_sequences.clear();
    d_->mpdu_sample_indexes.clear();
    d_->retry_mpdu_sample_indexes.clear();
    d_->set_anchor_indexes.clear();
    d_->previously_set_zero_anchor_indexes.clear();
    d_->hole_anchor_indexes.clear();
    d_->bad_fcs_anchor_indexes.clear();
    d_->bad_fcs_set_anchor_indexes.clear();
    d_->bad_fcs_zero_anchor_indexes.clear();
    d_->persistent_hole_spans.clear();
    d_->selected_frame = 0;

    int session_index = currentSessionIndex();
    if (session_index < 0 || session_index >= d_->sessions.size()) {
        d_->show_ssn_labels->setEnabled(false);
        d_->show_time_deltas->setEnabled(false);
        d_->show_ack_gaps->setEnabled(false);
        d_->show_mpdus->setEnabled(false);
        d_->show_persistent_holes->setEnabled(false);
        d_->show_bitmap_set->setEnabled(false);
        d_->show_holes->setEnabled(false);
        d_->show_agreement_events->setEnabled(false);
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
    int response_count = baResponseCount(session);
    bool have_responses = response_count > 0;
    QString key = sessionKey(session.ta, session.ra, session.tid);
    const auto mpdu_it = d_->captured_mpdus.constFind(key);
    const QVector<MpduSample> *mpdus = mpdu_it == d_->captured_mpdus.cend()
            ? nullptr : &mpdu_it.value();
    const auto agreement_it = d_->agreement_events.constFind(key);
    const QVector<AgreementEvent> *agreement_events =
            agreement_it == d_->agreement_events.cend() ? nullptr : &agreement_it.value();
    if (agreement_events) {
        d_->displayed_agreement_events = *agreement_events;
    }
    int mpdu_count = mpdus ? static_cast<int>(mpdus->size()) : 0;
    d_->show_ssn_labels->setEnabled(have_responses);
    d_->show_time_deltas->setEnabled(have_responses);
    d_->show_ack_gaps->setEnabled(have_responses);
    d_->show_mpdus->setEnabled(mpdu_count > 0);
    d_->show_persistent_holes->setEnabled(have_responses);
    d_->show_bitmap_set->setEnabled(have_responses);
    d_->show_holes->setEnabled(have_responses);
    d_->button_box->button(QDialogButtonBox::Save)->setEnabled(true);
    d_->button_box->button(QDialogButtonBox::Reset)->setEnabled(true);
    QVector<double> anchor_times;
    QVector<double> anchor_sequences;
    QVector<double> request_times;
    QVector<double> request_sequences;
    QVector<double> mpdu_times;
    QVector<double> mpdu_sequences;
    QVector<double> retry_mpdu_times;
    QVector<double> retry_mpdu_sequences;
    QVector<double> window_upper_times;
    QVector<double> window_upper_sequences;
    QVector<double> set_times;
    QVector<double> set_sequences;
    QVector<double> previously_set_zero_times;
    QVector<double> previously_set_zero_sequences;
    QVector<double> hole_times;
    QVector<double> hole_sequences;
    QVector<double> advance_span_times;
    QVector<double> advance_span_sequences;
    QVector<double> bad_fcs_anchor_times;
    QVector<double> bad_fcs_anchor_sequences;
    QVector<double> bad_fcs_window_upper_times;
    QVector<double> bad_fcs_window_upper_sequences;
    QVector<double> bad_fcs_set_times;
    QVector<double> bad_fcs_set_sequences;
    QVector<double> bad_fcs_zero_times;
    QVector<double> bad_fcs_zero_sequences;
    // A hole starts only as a zero below a later set bit. Once active, every
    // subsequent BA which covers it and still reports zero contributes to its
    // age, even when the zero is beyond that BA's highest set position.
    QHash<int, PersistentHoleTrack> active_holes;
    // Prevent a stale, backward BA from recreating a sequence which this epoch
    // already acknowledged or advanced past.
    QSet<int> acknowledged_sequences;
    // Retain explicit set-bit evidence for the entire agreement. The pruned
    // set above is sufficient for persistent-hole analysis but not for
    // classifying a later stale or backward BA bitmap.
    QSet<int> previously_set_sequences;
    int greatest_ssn = 0;
    bool have_greatest_ssn = false;
    auto finish_persistent_hole = [this](
            int sequence, const PersistentHoleTrack &track,
            PersistentHoleOutcome outcome, int endpoint_anchor_index,
            double endpoint_relative_time, uint32_t terminal_frame_number) {
        if (track.ba_count < 2 || endpoint_anchor_index < 0) {
            return;
        }
        PersistentHoleSpan span;
        span.unwrapped_sequence = sequence;
        span.endpoint_anchor_index = endpoint_anchor_index;
        span.first_frame_number = track.first_frame_number;
        span.first_relative_time = track.first_relative_time;
        span.endpoint_relative_time = endpoint_relative_time;
        span.terminal_frame_number = terminal_frame_number;
        span.ba_count = track.ba_count;
        span.outcome = outcome;
        d_->persistent_hole_spans.append(span);
    };
    // Exclusive frontier: the first trailing sequence without an observed BA ACK.
    int next_sequence_after_highest_ack = 0;
    bool have_ack_frontier = false;
    auto reset_ack_analysis = [&](PersistentHoleOutcome outcome,
                                  uint32_t terminal_frame_number) {
        const QList<int> active_sequences = active_holes.keys();
        for (int sequence : active_sequences) {
            const PersistentHoleTrack track = active_holes.value(sequence);
            finish_persistent_hole(
                        sequence, track, outcome, track.last_zero_anchor_index,
                        track.last_zero_relative_time, terminal_frame_number);
        }
        active_holes.clear();
        acknowledged_sequences.clear();
        previously_set_sequences.clear();
        have_greatest_ssn = false;
        next_sequence_after_highest_ack = 0;
        have_ack_frontier = false;
    };
    // BARs are plotted near the latest BA but must not affect BA unwrapping or analysis.
    uint32_t previous_ba_sequence = 0;
    int previous_ba_unwrapped = 0;
    bool have_previous_ba = false;
    int agreement_event_index = 0;

    for (int sample_index = 0; sample_index < session.samples.size(); sample_index++) {
        const BaSample &sample = session.samples.at(sample_index);
        while (agreement_events && agreement_event_index < agreement_events->size()) {
            const AgreementEvent &event = agreement_events->at(agreement_event_index);
            bool event_precedes_sample = event.relative_time < sample.relative_time ||
                    (event.relative_time == sample.relative_time &&
                     event.frame_number < sample.frame_number);
            if (!event_precedes_sample) {
                break;
            }
            if (agreementEventStartsAnalysis(event.type)) {
                reset_ack_analysis(PersistentHoleOutcome::AgreementStarted,
                                   event.frame_number);
                have_previous_ba = false;
            } else if (agreementEventEndsAnalysis(event.type)) {
                reset_ack_analysis(PersistentHoleOutcome::AgreementEnded,
                                   event.frame_number);
                have_previous_ba = false;
            }
            agreement_event_index++;
        }

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

        anchor_times.append(sample.relative_time);
        anchor_sequences.append(unwrapped);
        d_->anchor_sample_indexes.append(sample_index);
        d_->anchor_unwrapped_sequences.append(unwrapped);
        int anchor_index = static_cast<int>(d_->anchor_sample_indexes.size()) - 1;
        if (sample.explicit_fcs_error) {
            bad_fcs_anchor_times.append(sample.relative_time);
            bad_fcs_anchor_sequences.append(unwrapped);
            d_->bad_fcs_anchor_indexes.append(anchor_index);
        }

        int positions = bitmapPositionCount(sample);
        // The same TA/RA/TID can start a new BA epoch later in the capture.
        // A backward window wholly below the ACK frontier cannot extend the
        // current epoch, so start a new frontier. Modulo wrap has already been
        // unwrapped forward and does not satisfy this condition.
        bool epoch_reset = have_ack_frontier && ba_ssn_moved_backward &&
                unwrapped + positions <= next_sequence_after_highest_ack;
        if (epoch_reset) {
            reset_ack_analysis(PersistentHoleOutcome::EpochReset,
                               sample.frame_number);
            AgreementEvent reset_event;
            reset_event.frame_number = sample.frame_number;
            reset_event.relative_time = sample.relative_time;
            reset_event.type = AgreementEventType::InferredEpochReset;
            reset_event.explicit_fcs_error = sample.explicit_fcs_error;
            d_->displayed_agreement_events.append(reset_event);
        }
        previous_ba_sequence = sample.starting_sequence;
        previous_ba_unwrapped = unwrapped;
        have_previous_ba = true;
        window_upper_times.append(sample.relative_time);
        window_upper_sequences.append(unwrapped + positions);
        if (sample.explicit_fcs_error) {
            bad_fcs_window_upper_times.append(sample.relative_time);
            bad_fcs_window_upper_sequences.append(unwrapped + positions);
        }

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
        ssn_label->setText(QStringLiteral("%1 (%2)")
                           .arg(sample.starting_sequence)
                           .arg(bitmapSetBitCount(sample)));
        ssn_label->setPositionAlignment(Qt::AlignHCenter | Qt::AlignTop);
        ssn_label->setTextAlignment(Qt::AlignHCenter);
        ssn_label->setPadding(QMargins(0, 5, 0, 0));
        QFont label_font = d_->plot->font();
        label_font.setPointSize(8);
        ssn_label->setFont(label_font);
        ssn_label->setColor(QColor(sample.explicit_fcs_error
                                   ? tango_aluminium_5 : tango_sky_blue_5));
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

        if (!have_greatest_ssn || unwrapped > greatest_ssn) {
            greatest_ssn = unwrapped;
            have_greatest_ssn = true;
            QList<int> old_acknowledgments;
            for (int sequence : acknowledged_sequences) {
                if (sequence < greatest_ssn) {
                    old_acknowledgments.append(sequence);
                }
            }
            for (int sequence : old_acknowledgments) {
                acknowledged_sequences.remove(sequence);
            }
        }

        const QList<int> active_sequences = active_holes.keys();
        for (int sequence : active_sequences) {
            const PersistentHoleTrack track = active_holes.value(sequence);
            if (sequence < unwrapped) {
                finish_persistent_hole(
                            sequence, track, PersistentHoleOutcome::PassedBySsn,
                            anchor_index, sample.relative_time,
                            sample.frame_number);
                active_holes.remove(sequence);
                continue;
            }
            if (sequence >= unwrapped + positions) {
                finish_persistent_hole(
                            sequence, track, PersistentHoleOutcome::WindowInterrupted,
                            track.last_zero_anchor_index,
                            track.last_zero_relative_time, sample.frame_number);
                active_holes.remove(sequence);
                continue;
            }

            int position = sequence - unwrapped;
            if (bitmapPositionSet(sample, position)) {
                finish_persistent_hole(
                            sequence, track, PersistentHoleOutcome::Acknowledged,
                            anchor_index, sample.relative_time,
                            sample.frame_number);
                acknowledged_sequences.insert(sequence);
                active_holes.remove(sequence);
                continue;
            }

            PersistentHoleTrack &updated_track = active_holes[sequence];
            updated_track.last_zero_anchor_index = anchor_index;
            updated_track.last_zero_frame_number = sample.frame_number;
            updated_track.last_zero_relative_time = sample.relative_time;
            updated_track.ba_count++;
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
            int sequence = unwrapped + position;
            if (bitmapPositionSet(sample, position)) {
                set_times.append(sample.relative_time);
                set_sequences.append(sequence);
                d_->set_anchor_indexes.append(anchor_index);
                if (sample.explicit_fcs_error) {
                    bad_fcs_set_times.append(sample.relative_time);
                    bad_fcs_set_sequences.append(sequence);
                    d_->bad_fcs_set_anchor_indexes.append(anchor_index);
                }
                previously_set_sequences.insert(sequence);
                if (sequence >= greatest_ssn) {
                    acknowledged_sequences.insert(sequence);
                }
            } else {
                if (sample.explicit_fcs_error) {
                    bad_fcs_zero_times.append(sample.relative_time);
                    bad_fcs_zero_sequences.append(sequence);
                    d_->bad_fcs_zero_anchor_indexes.append(anchor_index);
                }
                if (previously_set_sequences.contains(sequence)) {
                    previously_set_zero_times.append(sample.relative_time);
                    previously_set_zero_sequences.append(sequence);
                    d_->previously_set_zero_anchor_indexes.append(anchor_index);
                } else {
                    hole_times.append(sample.relative_time);
                    hole_sequences.append(sequence);
                    d_->hole_anchor_indexes.append(anchor_index);
                    if (sequence >= greatest_ssn &&
                        !acknowledged_sequences.contains(sequence) &&
                        !active_holes.contains(sequence)) {
                        PersistentHoleTrack track;
                        track.first_frame_number = sample.frame_number;
                        track.first_relative_time = sample.relative_time;
                        track.last_zero_anchor_index = anchor_index;
                        track.last_zero_frame_number = sample.frame_number;
                        track.last_zero_relative_time = sample.relative_time;
                        track.ba_count = 1;
                        active_holes.insert(sequence, track);
                    }
                }
            }
        }
    }

    while (agreement_events && agreement_event_index < agreement_events->size()) {
        const AgreementEvent &event = agreement_events->at(agreement_event_index);
        if (agreementEventStartsAnalysis(event.type)) {
            reset_ack_analysis(PersistentHoleOutcome::AgreementStarted,
                               event.frame_number);
        } else if (agreementEventEndsAnalysis(event.type)) {
            reset_ack_analysis(PersistentHoleOutcome::AgreementEnded,
                               event.frame_number);
        }
        agreement_event_index++;
    }

    const QList<int> active_sequences = active_holes.keys();
    for (int sequence : active_sequences) {
        const PersistentHoleTrack track = active_holes.value(sequence);
        finish_persistent_hole(
                    sequence, track, PersistentHoleOutcome::Active,
                    track.last_zero_anchor_index,
                    track.last_zero_relative_time, track.last_zero_frame_number);
    }
    std::sort(d_->persistent_hole_spans.begin(), d_->persistent_hole_spans.end(),
              [](const PersistentHoleSpan &left, const PersistentHoleSpan &right) {
        if (left.endpoint_relative_time != right.endpoint_relative_time) {
            return left.endpoint_relative_time < right.endpoint_relative_time;
        }
        if (left.unwrapped_sequence != right.unwrapped_sequence) {
            return left.unwrapped_sequence < right.unwrapped_sequence;
        }
        return left.first_relative_time < right.first_relative_time;
    });

    if (mpdus) {
        int latest_anchor = -1;
        uint32_t previous_mpdu_sequence = 0;
        int previous_mpdu_unwrapped = 0;
        bool have_previous_mpdu = false;
        for (int mpdu_index = 0; mpdu_index < mpdus->size(); mpdu_index++) {
            const MpduSample &mpdu = mpdus->at(mpdu_index);
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

            if (mpdu.retry) {
                retry_mpdu_times.append(mpdu.relative_time);
                retry_mpdu_sequences.append(unwrapped);
                d_->retry_mpdu_sample_indexes.append(mpdu_index);
            } else {
                mpdu_times.append(mpdu.relative_time);
                mpdu_sequences.append(unwrapped);
                d_->mpdu_sample_indexes.append(mpdu_index);
            }
            d_->mpdu_unwrapped_sequences.append(unwrapped);
            previous_mpdu_sequence = mpdu.sequence;
            previous_mpdu_unwrapped = unwrapped;
            have_previous_mpdu = true;
        }
    }

    QVector<double> persistent_hole_end_times;
    QVector<double> persistent_hole_sequences;
    QVector<double> persistent_hole_durations;
    QVector<double> persistent_hole_error_plus;
    persistent_hole_end_times.reserve(d_->persistent_hole_spans.size());
    persistent_hole_sequences.reserve(d_->persistent_hole_spans.size());
    persistent_hole_durations.reserve(d_->persistent_hole_spans.size());
    persistent_hole_error_plus.reserve(d_->persistent_hole_spans.size());
    for (const PersistentHoleSpan &span : d_->persistent_hole_spans) {
        persistent_hole_end_times.append(span.endpoint_relative_time);
        persistent_hole_sequences.append(span.unwrapped_sequence);
        persistent_hole_durations.append(
                    span.endpoint_relative_time - span.first_relative_time);
        persistent_hole_error_plus.append(0.0);
    }

    d_->anchor_graph->setData(anchor_times, anchor_sequences, true);
    d_->request_graph->setData(request_times, request_sequences, true);
    d_->mpdu_graph->setData(mpdu_times, mpdu_sequences, true);
    d_->retry_mpdu_graph->setData(
                retry_mpdu_times, retry_mpdu_sequences, true);
    d_->window_upper_graph->setData(window_upper_times, window_upper_sequences, true);
    d_->set_graph->setData(set_times, set_sequences, true);
    d_->previously_set_zero_graph->setData(
                previously_set_zero_times, previously_set_zero_sequences, true);
    d_->hole_graph->setData(hole_times, hole_sequences, true);
    d_->persistent_hole_graph->setData(
                persistent_hole_end_times, persistent_hole_sequences, true);
    d_->persistent_hole_error_bars->setData(
                persistent_hole_durations, persistent_hole_error_plus);
    d_->advance_span_graph->setData(advance_span_times, advance_span_sequences, true);
    d_->bad_fcs_anchor_graph->setData(
                bad_fcs_anchor_times, bad_fcs_anchor_sequences, true);
    d_->bad_fcs_window_upper_graph->setData(
                bad_fcs_window_upper_times, bad_fcs_window_upper_sequences, true);
    d_->bad_fcs_set_graph->setData(
                bad_fcs_set_times, bad_fcs_set_sequences, true);
    d_->bad_fcs_zero_graph->setData(
                bad_fcs_zero_times, bad_fcs_zero_sequences, true);
    std::stable_sort(d_->displayed_agreement_events.begin(),
                     d_->displayed_agreement_events.end(),
                     [](const AgreementEvent &left, const AgreementEvent &right) {
        if (left.relative_time != right.relative_time) {
            return left.relative_time < right.relative_time;
        }
        if (left.frame_number != right.frame_number) {
            return left.frame_number < right.frame_number;
        }
        return static_cast<int>(left.type) < static_cast<int>(right.type);
    });
    drawAgreementEventMarkers();
    d_->show_agreement_events->setEnabled(
                !d_->displayed_agreement_events.isEmpty());
    d_->advance_span_graph->setVisible(d_->show_ack_gaps->isChecked());
    d_->mpdu_graph->setVisible(d_->show_mpdus->isChecked());
    d_->retry_mpdu_graph->setVisible(d_->show_mpdus->isChecked());
    bool show_persistent_holes = d_->show_persistent_holes->isChecked() &&
            !d_->persistent_hole_spans.isEmpty();
    d_->show_persistent_holes->setEnabled(!d_->persistent_hole_spans.isEmpty());
    d_->persistent_hole_graph->setVisible(show_persistent_holes);
    d_->persistent_hole_error_bars->setVisible(show_persistent_holes);
    d_->set_graph->setVisible(d_->show_bitmap_set->isChecked());
    d_->bad_fcs_set_graph->setVisible(d_->show_bitmap_set->isChecked());
    d_->previously_set_zero_graph->setVisible(d_->show_holes->isChecked());
    d_->hole_graph->setVisible(d_->show_holes->isChecked());
    d_->bad_fcs_zero_graph->setVisible(d_->show_holes->isChecked());
    if (d_->show_time_deltas->isChecked()) {
        drawTimeDeltaLabels();
    }

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
    if (!details_shown) {
        uint32_t preferred_event_frame = d_->agreement_retry_frame_aliases.value(
                    preferred_frame, preferred_frame);
        for (int event_index = 0;
             event_index < d_->displayed_agreement_events.size(); event_index++) {
            const AgreementEvent &event =
                    d_->displayed_agreement_events.at(event_index);
            if (event.frame_number == preferred_event_frame &&
                event.type != AgreementEventType::InferredEpochReset) {
                showAgreementEventDetails(event_index);
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

void WlanBlockAckGraphDialog::updateGraphSummary()
{
    if (currentSessionIndex() < 0) {
        return;
    }

    const QCPRange key_range = d_->plot->xAxis->range();
    const QCPRange value_range = d_->plot->yAxis->range();
    int persistent_hole_count = 0;
    for (const PersistentHoleSpan &span : d_->persistent_hole_spans) {
        if (value_range.contains(span.unwrapped_sequence) &&
            span.first_relative_time <= key_range.upper &&
            span.endpoint_relative_time >= key_range.lower) {
            persistent_hole_count++;
        }
    }
    int agreement_action_count = 0;
    int inferred_reset_count = 0;
    for (const AgreementEvent &event : d_->displayed_agreement_events) {
        if (!key_range.contains(event.relative_time)) {
            continue;
        }
        if (event.type == AgreementEventType::InferredEpochReset) {
            inferred_reset_count++;
        } else {
            agreement_action_count++;
        }
    }
    int retry_mpdu_count = graphPointCountInRange(
                d_->retry_mpdu_graph, key_range, value_range);
    int mpdu_count = retry_mpdu_count + graphPointCountInRange(
                d_->mpdu_graph, key_range, value_range);
    QString retry_rate = mpdu_count > 0
            ? tr("%1%").arg(QLocale().toString(
                                100.0 * retry_mpdu_count / mpdu_count, 'f', 1))
            : tr("n/a");

    d_->status_label->setText(
                tr("%1 session(s) available · X-axis duration: %2 · "
                   "In view: %3 BA / %4 BAR · %5 captured QoS Data MPDU(s) · "
                   "Observed MPDU retries: %6 / %5 (%7) · "
                   "%8 ADDBA/DELBA event(s) · %9 inferred SSN reset(s) · "
                   "%10 bitmap-set position(s) · %11 bitmap hole(s) · "
                   "%12 prior-set zero(s) · %13 persistent-hole lifetime(s) · "
                   "%14 no-BA-ACK-before-SSN-advance dot(s) · "
                   "%15 explicit-FCS-error BA(s) · "
                   "Capture totals: %16/%17 unsupported BA/BAR · "
                   "%18/%19 malformed BA/BAR")
                .arg(d_->sessions.size())
                .arg(durationLabel(key_range.size()))
                .arg(graphPointCountInRange(d_->anchor_graph, key_range, value_range))
                .arg(graphPointCountInRange(d_->request_graph, key_range, value_range))
                .arg(mpdu_count)
                .arg(retry_mpdu_count)
                .arg(retry_rate)
                .arg(agreement_action_count)
                .arg(inferred_reset_count)
                .arg(graphPointCountInRange(d_->set_graph, key_range, value_range))
                .arg(graphPointCountInRange(d_->hole_graph, key_range, value_range))
                .arg(graphPointCountInRange(d_->previously_set_zero_graph,
                                            key_range, value_range))
                .arg(persistent_hole_count)
                .arg(graphPointCountInRange(d_->advance_span_graph,
                                            key_range, value_range))
                .arg(graphPointCountInRange(d_->bad_fcs_anchor_graph,
                                            key_range, value_range))
                .arg(d_->unsupported_ba_frames)
                .arg(d_->unsupported_bar_frames)
                .arg(d_->malformed_ba_frames)
                .arg(d_->malformed_bar_frames));
}

void WlanBlockAckGraphDialog::clearAgreementEventMarkers()
{
    for (QCPItemLine *line : d_->agreement_event_lines) {
        d_->plot->removeItem(line);
    }
    for (QCPItemText *label : d_->agreement_event_labels) {
        d_->plot->removeItem(label);
    }
    d_->agreement_event_lines.clear();
    d_->agreement_event_labels.clear();
    d_->displayed_agreement_events.clear();
}

void WlanBlockAckGraphDialog::drawAgreementEventMarkers()
{
    bool visible = d_->show_agreement_events->isChecked();
    for (int event_index = 0;
         event_index < d_->displayed_agreement_events.size(); event_index++) {
        const AgreementEvent &event =
                d_->displayed_agreement_events.at(event_index);
        QColor event_color = agreementEventColor(event);
        QColor line_color = event_color;
        line_color.setAlpha(190);
        QPen line_pen(line_color,
                      agreementEventResetsAnalysis(event.type) ? 1.6 : 1.2,
                      agreementEventPenStyle(event.type));

        QCPItemLine *line = new QCPItemLine(d_->plot);
        line->setObjectName(QStringLiteral("baAgreementEventLine_%1_%2")
                            .arg(event.frame_number)
                            .arg(event_index));
        line->start->setAxes(d_->plot->xAxis, d_->plot->yAxis);
        line->end->setAxes(d_->plot->xAxis, d_->plot->yAxis);
        line->start->setAxisRect(d_->plot->axisRect());
        line->end->setAxisRect(d_->plot->axisRect());
        line->start->setTypeX(QCPItemPosition::ptPlotCoords);
        line->start->setTypeY(QCPItemPosition::ptAxisRectRatio);
        line->end->setTypeX(QCPItemPosition::ptPlotCoords);
        line->end->setTypeY(QCPItemPosition::ptAxisRectRatio);
        line->start->setCoords(event.relative_time, 0.0);
        line->end->setCoords(event.relative_time, 1.0);
        line->setPen(line_pen);
        QPen selected_pen(event_color, 3.0, agreementEventPenStyle(event.type));
        line->setSelectedPen(selected_pen);
        line->setSelectable(true);
        line->setClipAxisRect(d_->plot->axisRect());
        line->setClipToAxisRect(true);
        line->setLayer(QStringLiteral("baAgreementEvents"));
        line->setVisible(visible);
        d_->agreement_event_lines.append(line);

        int label_lane = 0;
        switch (event.type) {
        case AgreementEventType::AddbaRequest:
            label_lane = 0;
            break;
        case AgreementEventType::AddbaResponseAccepted:
        case AgreementEventType::AddbaResponseRejected:
            label_lane = 1;
            break;
        case AgreementEventType::Delba:
        case AgreementEventType::InferredEpochReset:
            label_lane = 2;
            break;
        }

        QCPItemText *label = new QCPItemText(d_->plot);
        label->setObjectName(QStringLiteral("baAgreementEventLabel_%1_%2")
                             .arg(event.frame_number)
                             .arg(event_index));
        label->position->setAxes(d_->plot->xAxis, d_->plot->yAxis);
        label->position->setAxisRect(d_->plot->axisRect());
        label->position->setTypeX(QCPItemPosition::ptPlotCoords);
        label->position->setTypeY(QCPItemPosition::ptAxisRectRatio);
        label->position->setCoords(event.relative_time,
                                   0.015 + 0.065 * label_lane);
        label->setText(agreementEventLabel(event));
        label->setPositionAlignment(Qt::AlignHCenter | Qt::AlignTop);
        label->setTextAlignment(Qt::AlignHCenter);
        label->setPadding(QMargins(3, 1, 3, 1));
        QFont label_font = d_->plot->font();
        label_font.setPointSize(8);
        label_font.setBold(agreementEventResetsAnalysis(event.type));
        label->setFont(label_font);
        QFont selected_font = label_font;
        selected_font.setBold(true);
        label->setSelectedFont(selected_font);
        label->setColor(event_color);
        label->setSelectedColor(event_color.darker(130));
        label->setPen(QPen(event_color, 0.8));
        label->setSelectedPen(QPen(event_color, 1.8));
        // QCustomPlot's canvas is explicitly white even when the application
        // palette is dark, so keep compact labels legible against that canvas.
        QColor label_background(Qt::white);
        label_background.setAlpha(220);
        label->setBrush(QBrush(label_background));
        label_background.setAlpha(245);
        label->setSelectedBrush(QBrush(label_background));
        label->setSelectable(true);
        label->setClipAxisRect(d_->plot->axisRect());
        label->setClipToAxisRect(true);
        label->setLayer(QStringLiteral("baAgreementEventLabels"));
        label->setVisible(visible);
        d_->agreement_event_labels.append(label);
    }
    updateAgreementEventLabelVisibility();
}

void WlanBlockAckGraphDialog::updateAgreementEventLabelVisibility()
{
    bool show_events = d_->show_agreement_events->isChecked();
    const QCPRange key_range = d_->plot->xAxis->range();
    int last_label_pixels[] = {-1000000, -1000000, -1000000};

    for (int event_index = 0;
         event_index < d_->displayed_agreement_events.size(); event_index++) {
        const AgreementEvent &event =
                d_->displayed_agreement_events.at(event_index);
        if (event_index < d_->agreement_event_lines.size()) {
            d_->agreement_event_lines.at(event_index)->setVisible(show_events);
        }
        if (event_index >= d_->agreement_event_labels.size()) {
            continue;
        }

        int label_lane = 0;
        if (event.type == AgreementEventType::AddbaResponseAccepted ||
            event.type == AgreementEventType::AddbaResponseRejected) {
            label_lane = 1;
        } else if (event.type == AgreementEventType::Delba ||
                   event.type == AgreementEventType::InferredEpochReset) {
            label_lane = 2;
        }
        int event_pixel = qRound(d_->plot->xAxis->coordToPixel(event.relative_time));
        bool label_visible = show_events && key_range.contains(event.relative_time) &&
                event_pixel - last_label_pixels[label_lane] >=
                min_agreement_event_label_spacing;
        d_->agreement_event_labels.at(event_index)->setVisible(label_visible);
        if (label_visible) {
            last_label_pixels[label_lane] = event_pixel;
        }
    }
}

void WlanBlockAckGraphDialog::clearAgreementEventSelection()
{
    for (QCPItemLine *line : d_->agreement_event_lines) {
        line->setSelected(false);
    }
    for (QCPItemText *label : d_->agreement_event_labels) {
        label->setSelected(false);
    }
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
    clearAgreementEventSelection();

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
    QString fcs_detail = sample.explicit_fcs_error
            ? tr(" · explicit FCS error; plotted in gray") : QString();

    d_->details_label->setText(
                tr("Frame %1 · %2 BA · TA %3 → RA %4 · TID %5 · SSN %6 "
                   "(unwrapped %7) · window upper bound %8 (unwrapped %9, exclusive) · "
                   "%10%11. Click a BA point to go to this frame.")
                .arg(sample.frame_number)
                .arg(blockAckTypeName(sample.type))
                .arg(d_->sessions.at(session_index).ta,
                     d_->sessions.at(session_index).ra)
                .arg(sample.tid)
                .arg(sample.starting_sequence)
                .arg(d_->anchor_unwrapped_sequences.at(data_index))
                .arg(upper_bound)
                .arg(unwrapped_upper_bound)
                .arg(bitmap_detail)
                .arg(fcs_detail));

    d_->request_graph->setSelection(QCPDataSelection());
    d_->mpdu_graph->setSelection(QCPDataSelection());
    d_->retry_mpdu_graph->setSelection(QCPDataSelection());
    d_->persistent_hole_graph->setSelection(QCPDataSelection());
    int bad_fcs_index = static_cast<int>(
                d_->bad_fcs_anchor_indexes.indexOf(data_index));
    d_->anchor_graph->setSelection(bad_fcs_index >= 0
            ? QCPDataSelection()
            : QCPDataSelection(QCPDataRange(data_index, data_index + 1)));
    d_->bad_fcs_anchor_graph->setSelection(bad_fcs_index >= 0
            ? QCPDataSelection(QCPDataRange(bad_fcs_index, bad_fcs_index + 1))
            : QCPDataSelection());
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
    clearAgreementEventSelection();

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
    d_->bad_fcs_anchor_graph->setSelection(QCPDataSelection());
    d_->mpdu_graph->setSelection(QCPDataSelection());
    d_->retry_mpdu_graph->setSelection(QCPDataSelection());
    d_->persistent_hole_graph->setSelection(QCPDataSelection());
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
    clearAgreementEventSelection();
    d_->details_label->setText(
                tr("Frame %1 · Captured QoS Data MPDU · TA %2 → RA %3 · TID %4 · "
                   "sequence %5 (unwrapped %6) · Retry bit %7. Capture presence does not "
                   "prove reception by the destination. Click an MPDU point to go to this "
                   "frame.")
                .arg(mpdu.frame_number)
                .arg(session.ra, session.ta)
                .arg(session.tid)
                .arg(mpdu.sequence)
                .arg(d_->mpdu_unwrapped_sequences.at(data_index))
                .arg(mpdu.retry ? tr("set") : tr("clear")));

    d_->anchor_graph->setSelection(QCPDataSelection());
    d_->bad_fcs_anchor_graph->setSelection(QCPDataSelection());
    d_->request_graph->setSelection(QCPDataSelection());
    d_->persistent_hole_graph->setSelection(QCPDataSelection());
    int mpdu_graph_index = static_cast<int>(
                d_->mpdu_sample_indexes.indexOf(data_index));
    int retry_mpdu_graph_index = static_cast<int>(
                d_->retry_mpdu_sample_indexes.indexOf(data_index));
    d_->mpdu_graph->setSelection(mpdu_graph_index >= 0
            ? QCPDataSelection(QCPDataRange(mpdu_graph_index,
                                            mpdu_graph_index + 1))
            : QCPDataSelection());
    d_->retry_mpdu_graph->setSelection(retry_mpdu_graph_index >= 0
            ? QCPDataSelection(QCPDataRange(retry_mpdu_graph_index,
                                            retry_mpdu_graph_index + 1))
            : QCPDataSelection());
    d_->plot->replot(QCustomPlot::rpQueuedReplot);
}

void WlanBlockAckGraphDialog::showPersistentHoleDetails(int data_index)
{
    int session_index = currentSessionIndex();
    if (session_index < 0 || session_index >= d_->sessions.size() ||
        data_index < 0 || data_index >= d_->persistent_hole_spans.size()) {
        return;
    }

    const PersistentHoleSpan &span = d_->persistent_hole_spans.at(data_index);
    if (span.endpoint_anchor_index < 0 ||
        span.endpoint_anchor_index >= d_->anchor_sample_indexes.size()) {
        return;
    }

    const BaSession &session = d_->sessions.at(session_index);
    int sample_index = d_->anchor_sample_indexes.at(span.endpoint_anchor_index);
    const BaSample &sample = session.samples.at(sample_index);
    d_->selected_frame = sample.frame_number;
    clearAgreementEventSelection();

    QString outcome;
    switch (span.outcome) {
    case PersistentHoleOutcome::Acknowledged:
        outcome = tr("acknowledged by this BA");
        break;
    case PersistentHoleOutcome::PassedBySsn:
        outcome = tr("passed by this BA SSN without an observed acknowledgment");
        break;
    case PersistentHoleOutcome::WindowInterrupted:
        outcome = tr("last covered here; BA frame %1 no longer covered this sequence")
                .arg(span.terminal_frame_number);
        break;
    case PersistentHoleOutcome::AgreementStarted:
        outcome = tr("last covered here; successful ADDBA response frame %1 began a new "
                     "agreement")
                .arg(span.terminal_frame_number);
        break;
    case PersistentHoleOutcome::AgreementEnded:
        outcome = tr("last covered here; DELBA frame %1 ended the agreement")
                .arg(span.terminal_frame_number);
        break;
    case PersistentHoleOutcome::EpochReset:
        outcome = tr("last covered here; BA frame %1 began a new analysis epoch")
                .arg(span.terminal_frame_number);
        break;
    case PersistentHoleOutcome::Active:
        outcome = tr("still unacknowledged in the last covering BA");
        break;
    }

    QString elapsed = gchar_free_to_qstring(
                format_units(nullptr,
                             span.endpoint_relative_time - span.first_relative_time,
                             FORMAT_SIZE_UNIT_SECONDS, FORMAT_SIZE_PREFIX_SI, 3));
    d_->details_label->setText(
                tr("Frame %1 · Persistent BA bitmap hole · TA %2 → RA %3 · TID %4 · "
                   "sequence %5 (unwrapped %6) · %7 consecutive covering BA responses "
                   "without an ACK · lifetime span %8 · first observed in frame %9 · %10. "
                   "Click a lifetime endpoint to go to this frame.")
                .arg(sample.frame_number)
                .arg(session.ta, session.ra)
                .arg(session.tid)
                .arg(wrappedSequence(span.unwrapped_sequence))
                .arg(span.unwrapped_sequence)
                .arg(span.ba_count)
                .arg(elapsed)
                .arg(span.first_frame_number)
                .arg(outcome));

    d_->anchor_graph->setSelection(QCPDataSelection());
    d_->bad_fcs_anchor_graph->setSelection(QCPDataSelection());
    d_->request_graph->setSelection(QCPDataSelection());
    d_->mpdu_graph->setSelection(QCPDataSelection());
    d_->retry_mpdu_graph->setSelection(QCPDataSelection());
    d_->persistent_hole_graph->setSelection(
                QCPDataSelection(QCPDataRange(data_index, data_index + 1)));
    d_->plot->replot(QCustomPlot::rpQueuedReplot);
}

void WlanBlockAckGraphDialog::showAgreementEventDetails(int event_index)
{
    int session_index = currentSessionIndex();
    if (session_index < 0 || session_index >= d_->sessions.size() ||
        event_index < 0 || event_index >= d_->displayed_agreement_events.size()) {
        return;
    }

    const BaSession &session = d_->sessions.at(session_index);
    const AgreementEvent &agreement_event =
            d_->displayed_agreement_events.at(event_index);
    d_->selected_frame = agreement_event.frame_number;

    QString event_name;
    QString sender;
    QString receiver;
    QString analysis_effect;
    switch (agreement_event.type) {
    case AgreementEventType::AddbaRequest:
        event_name = tr("ADDBA Request");
        sender = session.ra;
        receiver = session.ta;
        analysis_effect = tr("This proposal does not reset the graph's agreement state; "
                             "an accepted response does");
        break;
    case AgreementEventType::AddbaResponseAccepted:
        event_name = tr("accepted ADDBA Response");
        sender = session.ta;
        receiver = session.ra;
        analysis_effect = tr("This starts a new Block Ack agreement and resets prior "
                             "bitmap, ACK-frontier, and persistent-hole state");
        break;
    case AgreementEventType::AddbaResponseRejected:
        event_name = tr("rejected ADDBA Response");
        sender = session.ta;
        receiver = session.ra;
        analysis_effect = tr("This does not start a Block Ack agreement or reset the "
                             "graph's agreement state");
        break;
    case AgreementEventType::Delba:
        event_name = tr("DELBA (%1 initiated)")
                .arg(agreement_event.sender_is_originator
                     ? tr("originator") : tr("recipient"));
        sender = agreement_event.sender_is_originator ? session.ra : session.ta;
        receiver = agreement_event.sender_is_originator ? session.ta : session.ra;
        analysis_effect = tr("This ends the Block Ack agreement and resets prior bitmap, "
                             "ACK-frontier, and persistent-hole state");
        break;
    case AgreementEventType::InferredEpochReset:
        event_name = tr("inferred SSN epoch reset");
        sender = session.ta;
        receiver = session.ra;
        analysis_effect = tr("This BA moved backward into a window wholly below the prior "
                             "ACK frontier. No captured ADDBA/DELBA boundary explained the "
                             "change, so the graph began a new analysis epoch and reset its "
                             "prior state");
        break;
    }

    QString detail = tr("Frame %1 · %2 · sender %3 → receiver %4 · "
                        "BA session %5 → %6 · TID %7")
            .arg(agreement_event.frame_number)
            .arg(event_name)
            .arg(sender, receiver)
            .arg(session.ta, session.ra)
            .arg(session.tid);
    if (agreement_event.has_dialog_token) {
        detail += tr(" · dialog token %1").arg(agreement_event.dialog_token);
    }
    if (agreement_event.has_starting_sequence) {
        detail += tr(" · proposed SSN %1").arg(agreement_event.starting_sequence);
    }
    if (agreement_event.has_status_code) {
        detail += agreement_event.status_text.isEmpty()
                ? tr(" · status code %1").arg(agreement_event.status_code)
                : tr(" · status code %1 (%2)")
                  .arg(agreement_event.status_code)
                  .arg(agreement_event.status_text);
    }
    if (agreement_event.has_reason_code) {
        detail += agreement_event.reason_text.isEmpty()
                ? tr(" · reason code %1").arg(agreement_event.reason_code)
                : tr(" · reason code %1 (%2)")
                  .arg(agreement_event.reason_code)
                  .arg(agreement_event.reason_text);
    }
    if (agreement_event.explicit_fcs_error) {
        detail += tr(" · explicit FCS error; plotted in gray");
    }
    detail += tr(" · %1. Click the event marker to go to this frame.")
            .arg(analysis_effect);
    d_->details_label->setText(detail);

    d_->anchor_graph->setSelection(QCPDataSelection());
    d_->bad_fcs_anchor_graph->setSelection(QCPDataSelection());
    d_->request_graph->setSelection(QCPDataSelection());
    d_->mpdu_graph->setSelection(QCPDataSelection());
    d_->retry_mpdu_graph->setSelection(QCPDataSelection());
    d_->persistent_hole_graph->setSelection(QCPDataSelection());
    clearAgreementEventSelection();
    if (event_index < d_->agreement_event_lines.size()) {
        d_->agreement_event_lines.at(event_index)->setSelected(true);
    }
    if (event_index < d_->agreement_event_labels.size()) {
        d_->agreement_event_labels.at(event_index)->setSelected(true);
    }
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
    if (plottable == d_->previously_set_zero_graph &&
        data_index < d_->previously_set_zero_anchor_indexes.size()) {
        return d_->previously_set_zero_anchor_indexes.at(data_index);
    }
    if (plottable == d_->hole_graph && data_index < d_->hole_anchor_indexes.size()) {
        return d_->hole_anchor_indexes.at(data_index);
    }
    if ((plottable == d_->bad_fcs_anchor_graph ||
         plottable == d_->bad_fcs_window_upper_graph) &&
        data_index < d_->bad_fcs_anchor_indexes.size()) {
        return d_->bad_fcs_anchor_indexes.at(data_index);
    }
    if (plottable == d_->bad_fcs_set_graph &&
        data_index < d_->bad_fcs_set_anchor_indexes.size()) {
        return d_->bad_fcs_set_anchor_indexes.at(data_index);
    }
    if (plottable == d_->bad_fcs_zero_graph &&
        data_index < d_->bad_fcs_zero_anchor_indexes.size()) {
        return d_->bad_fcs_zero_anchor_indexes.at(data_index);
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
    d_->retry_mpdu_graph->setVisible(checked);
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::persistentHolesToggled(bool checked)
{
    d_->persistent_hole_graph->setVisible(checked);
    d_->persistent_hole_error_bars->setVisible(checked);
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::bitmapSetToggled(bool checked)
{
    d_->set_graph->setVisible(checked);
    d_->bad_fcs_set_graph->setVisible(checked);
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::bitmapHolesToggled(bool checked)
{
    d_->previously_set_zero_graph->setVisible(checked);
    d_->hole_graph->setVisible(checked);
    d_->bad_fcs_zero_graph->setVisible(checked);
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::agreementEventsToggled(bool)
{
    updateAgreementEventLabelVisibility();
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::mouseZoomToggled(bool checked)
{
    QCP::Interactions interactions = QCP::iRangeZoom |
            QCP::iSelectPlottables | QCP::iSelectItems;
    if (checked) {
        d_->plot->setCursor(QCursor(Qt::CrossCursor));
    } else {
        interactions |= QCP::iRangeDrag;
        if (d_->zoom_rubber_band) {
            d_->zoom_rubber_band->hide();
        }
        d_->plot->unsetCursor();
    }
    d_->plot->setInteractions(interactions);
}

void WlanBlockAckGraphDialog::plotMousePressed(QMouseEvent *event)
{
    if (!event || event->button() != Qt::LeftButton ||
        !d_->mouse_zoom_radio->isChecked() ||
        !d_->plot->axisRect()->rect().contains(event->pos())) {
        return;
    }

    if (!d_->zoom_rubber_band) {
        d_->zoom_rubber_band = new QRubberBand(QRubberBand::Rectangle, d_->plot);
    }
    d_->zoom_origin = event->pos();
    d_->zoom_rubber_band->setGeometry(QRect(d_->zoom_origin, QSize()));
    d_->zoom_rubber_band->show();
}

void WlanBlockAckGraphDialog::plotMouseMoved(QMouseEvent *event)
{
    if (!event || !d_->zoom_rubber_band || !d_->zoom_rubber_band->isVisible() ||
        !event->buttons().testFlag(Qt::LeftButton)) {
        return;
    }
    d_->zoom_rubber_band->setGeometry(
                QRect(d_->zoom_origin, event->pos()).normalized());
}

void WlanBlockAckGraphDialog::plotMouseReleased(QMouseEvent *event)
{
    if (!event || event->button() != Qt::LeftButton ||
        !d_->zoom_rubber_band || !d_->zoom_rubber_band->isVisible()) {
        return;
    }

    d_->zoom_rubber_band->hide();
    if (!d_->mouse_zoom_radio->isChecked()) {
        return;
    }

    QRectF zoom_ranges = zoomRanges(d_->plot, QRect(d_->zoom_origin, event->pos()));
    if (zoom_ranges.width() <= 0.0 || zoom_ranges.height() <= 0.0) {
        return;
    }

    d_->plot->xAxis->setRange(zoom_ranges.left(), zoom_ranges.right());
    d_->plot->yAxis->setRange(zoom_ranges.top(), zoom_ranges.bottom());
    d_->plot->replot();
}

void WlanBlockAckGraphDialog::plotClicked(QCPAbstractPlottable *plottable,
                                          int data_index, QMouseEvent *event)
{
    if (!event || event->button() != Qt::LeftButton) {
        return;
    }

    bool sample_selected = false;
    if (plottable == d_->persistent_hole_graph &&
        data_index >= 0 && data_index < d_->persistent_hole_spans.size()) {
        showPersistentHoleDetails(data_index);
        sample_selected = true;
    } else if ((plottable == d_->mpdu_graph ||
                plottable == d_->retry_mpdu_graph) && data_index >= 0) {
        const QVector<int> &sample_indexes = plottable == d_->mpdu_graph
                ? d_->mpdu_sample_indexes : d_->retry_mpdu_sample_indexes;
        if (data_index < sample_indexes.size()) {
            showMpduDetails(sample_indexes.at(data_index));
            sample_selected = true;
        }
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

void WlanBlockAckGraphDialog::plotItemClicked(QCPAbstractItem *item,
                                               QMouseEvent *event)
{
    if (!item || !event || event->button() != Qt::LeftButton) {
        return;
    }

    for (int event_index = 0;
         event_index < d_->displayed_agreement_events.size(); event_index++) {
        bool line_clicked = event_index < d_->agreement_event_lines.size() &&
                item == d_->agreement_event_lines.at(event_index);
        bool label_clicked = event_index < d_->agreement_event_labels.size() &&
                item == d_->agreement_event_labels.at(event_index);
        if (!line_clicked && !label_clicked) {
            continue;
        }
        showAgreementEventDetails(event_index);
        if (!file_closed_ && d_->selected_frame > 0) {
            emit goToPacket(static_cast<int>(d_->selected_frame));
        }
        return;
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
            (!d_->mpdu_graph->data()->isEmpty() ||
             !d_->retry_mpdu_graph->data()->isEmpty());
    bool agreement_events_visible = d_->show_agreement_events->isChecked() &&
            !d_->displayed_agreement_events.isEmpty();
    if (d_->anchor_graph->data()->isEmpty() &&
        d_->request_graph->data()->isEmpty() && !mpdus_visible &&
        !agreement_events_visible) {
        d_->plot->xAxis->setRange(0.0, 1.0);
        d_->plot->yAxis->setRange(0.0, 1.0);
        d_->plot->replot();
        return;
    }

    bool have_x_range = false;
    QCPRange x_range;
    const QVector<QCPGraph *> time_graphs = {
        d_->anchor_graph, d_->request_graph,
        mpdus_visible ? d_->mpdu_graph : nullptr,
        mpdus_visible ? d_->retry_mpdu_graph : nullptr
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
    bool have_sample_x_range = have_x_range;
    if (agreement_events_visible) {
        for (const AgreementEvent &event : d_->displayed_agreement_events) {
            // Always fit boundaries which reset analysis. Requests and rejected
            // responses remain visible when they are near the plotted traffic,
            // but an old failed negotiation must not flatten a later BA trace.
            if (have_sample_x_range &&
                !agreementEventResetsAnalysis(event.type)) {
                continue;
            }
            if (have_x_range) {
                x_range.expand(event.relative_time);
            } else {
                x_range = QCPRange(event.relative_time, event.relative_time);
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
        d_->anchor_graph, d_->request_graph, d_->window_upper_graph,
        d_->show_bitmap_set->isChecked() ? d_->set_graph : nullptr,
        d_->show_holes->isChecked() ? d_->previously_set_zero_graph : nullptr,
        d_->show_holes->isChecked() ? d_->hole_graph : nullptr,
        d_->show_persistent_holes->isChecked() ? d_->persistent_hole_graph : nullptr,
        d_->show_ack_gaps->isChecked() ? d_->advance_span_graph : nullptr,
        mpdus_visible ? d_->mpdu_graph : nullptr,
        mpdus_visible ? d_->retry_mpdu_graph : nullptr
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
