/* wlan_connection_timeline_dialog.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "wlan_connection_timeline_dialog.h"

#include <epan/epan_dissect.h>
#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/stat_tap_ui.h>
#include <epan/strutil.h>
#include <epan/tap.h>

#include <epan/dissectors/packet-ieee80211.h>

#include <QApplication>
#include <QHash>
#include <QStyle>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVector>

#include "main_application.h"
#include <ui/qt/utils/qt_ui_utils.h>

namespace {

enum Column {
    col_station,
    col_bssid,
    col_ssid,
    col_event,
    col_direction,
    col_result,
    col_time,
    col_delta,
    col_frame
};

enum RowType {
    connection_row_type = QTreeWidgetItem::UserType,
    event_row_type
};

enum class EventType {
    ProbeRequest,
    ProbeResponse,
    AuthenticationRequest,
    AuthenticationResponse,
    AssociationRequest,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    PairwiseKey,
    GroupKey,
    Disassociation,
    Deauthentication
};

enum class ConnectionState {
    None,
    Discovery,
    Authenticating,
    Authenticated,
    AuthenticationFailed,
    Associating,
    Associated,
    AssociationFailed,
    Securing,
    Connected,
    Disconnected
};

const int sort_role = Qt::UserRole;
constexpr uint32_t auth_algorithm_fast_bss_transition = 2;
constexpr uint32_t auth_algorithm_shared_key = 1;
constexpr uint32_t sae_message_commit = 1;
constexpr uint32_t status_sae_anti_clogging_token_required = 76;
constexpr uint32_t status_sae_hash_to_element = 126;

struct TimelineEvent {
    EventType type;
    uint32_t frame_number;
    double relative_time;
    QString station;
    QString bssid;
    QString ssid;
    QString name;
    QString direction;
    QString result;
    int status_code = -1;
    int key_message = -1;
    bool retry = false;
    bool fast_transition = false;
    bool authentication_complete = true;
    bool bssid_wide = false;
};

using FieldIds = QVector<int>;

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

static const field_info *firstField(epan_dissect *edt, const FieldIds &hf_ids)
{
    if (!edt || !edt->tree || hf_ids.isEmpty()) {
        return nullptr;
    }

    for (int hf_id : hf_ids) {
        GPtrArray *fields = proto_get_finfo_ptr_array(edt->tree, hf_id);
        if (fields && fields->len > 0) {
            return static_cast<const field_info *>(fields->pdata[0]);
        }
    }

    // The listener filter primes every field used by this dialog. Keep this
    // fallback for captures dissected with an always-visible protocol tree.
    for (int hf_id : hf_ids) {
        GPtrArray *fields = proto_find_first_finfo(edt->tree, hf_id);
        const field_info *field = nullptr;
        if (fields && fields->len > 0) {
            field = static_cast<const field_info *>(fields->pdata[0]);
        }
        if (fields) {
            g_ptr_array_free(fields, true);
        }
        if (field) {
            return field;
        }
    }
    return nullptr;
}

static bool fieldUnsigned(epan_dissect *edt, const FieldIds &hf_ids, uint32_t &value)
{
    const field_info *field = firstField(edt, hf_ids);
    if (!field) {
        return false;
    }
    value = fvalue_get_uinteger(field->value);
    return true;
}

static bool fieldUnsigned64(epan_dissect *edt, const FieldIds &hf_ids, uint64_t &value)
{
    const field_info *field = firstField(edt, hf_ids);
    if (!field) {
        return false;
    }
    value = fvalue_get_uinteger64(field->value);
    return true;
}

static QString fieldDisplay(epan_dissect *edt, const FieldIds &hf_ids)
{
    const field_info *field = firstField(edt, hf_ids);
    if (!field) {
        return QString();
    }

    char display_label[ITEM_LABEL_LENGTH];
    int length = proto_item_fill_display_label(field, display_label, ITEM_LABEL_LENGTH);
    if (length < 1) {
        return QString();
    }
    return QString::fromUtf8(display_label, length);
}

static QString ssidFromHeader(const wlan_hdr_t *wlan_hdr)
{
    if (!wlan_hdr || wlan_hdr->stats.ssid_len == 0) {
        return QString();
    }
    if (wlan_hdr->stats.ssid_len == 1 && wlan_hdr->stats.ssid[0] == 0) {
        return QObject::tr("<Hidden>");
    }

    char *ssid = format_text(nullptr, reinterpret_cast<const char *>(wlan_hdr->stats.ssid),
                             wlan_hdr->stats.ssid_len);
    QString result = QString::fromUtf8(ssid);
    wmem_free(nullptr, ssid);
    return result;
}

static bool isDiscoveryEvent(EventType type)
{
    return type == EventType::ProbeRequest || type == EventType::ProbeResponse;
}

static bool isBroadcastWlanAddress(const address *addr)
{
    static const uint8_t broadcast_address[6] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    return addr && addr->len == static_cast<int>(sizeof(broadcast_address)) &&
            memcmp(addr->data, broadcast_address, sizeof(broadcast_address)) == 0;
}

static bool startsConnectionAttempt(EventType type)
{
    return type == EventType::AuthenticationRequest ||
           type == EventType::AssociationRequest ||
           type == EventType::ReassociationRequest;
}

class TimelineTreeWidgetItem : public QTreeWidgetItem
{
public:
    explicit TimelineTreeWidgetItem(QTreeWidget *parent, int type) :
        QTreeWidgetItem(parent, type)
    {
    }

    explicit TimelineTreeWidgetItem(QTreeWidgetItem *parent, int type) :
        QTreeWidgetItem(parent, type)
    {
    }

    bool operator<(const QTreeWidgetItem &other) const override
    {
        int column = treeWidget() ? treeWidget()->sortColumn() : 0;
        QVariant left = data(column, sort_role);
        QVariant right = other.data(column, sort_role);
        if (left.isValid() && right.isValid()) {
            return left.toDouble() < right.toDouble();
        }
        return QString::localeAwareCompare(text(column), other.text(column)) < 0;
    }
};

class TimelineEventTreeWidgetItem : public TimelineTreeWidgetItem
{
public:
    TimelineEventTreeWidgetItem(QTreeWidgetItem *parent, const TimelineEvent &event,
                                double previous_time) :
        TimelineTreeWidgetItem(parent, event_row_type),
        event_(event)
    {
        double delta_ms = (event.relative_time - previous_time) * 1000.0;

        setText(col_event, event.name);
        setText(col_direction, event.direction);
        setText(col_result, event.result);
        setText(col_time, QString::number(event.relative_time, 'f', 6));
        setText(col_delta, QString::number(delta_ms, 'f', 3));
        setText(col_frame, QString::number(event.frame_number));
        setData(col_time, sort_role, event.relative_time);
        setData(col_delta, sort_role, delta_ms);
        setData(col_frame, sort_role, event.frame_number);
        setToolTip(col_event, QObject::tr("Double-click to jump to frame %1.")
                   .arg(event.frame_number));

        if (event.status_code > 0) {
            setIcon(col_result, QApplication::style()->standardIcon(QStyle::SP_MessageBoxCritical));
        } else if (event.type == EventType::Disassociation ||
                   event.type == EventType::Deauthentication) {
            setIcon(col_result, QApplication::style()->standardIcon(QStyle::SP_MessageBoxWarning));
        } else if (event.type == EventType::PairwiseKey && event.key_message == 4) {
            setIcon(col_result, QApplication::style()->standardIcon(QStyle::SP_DialogApplyButton));
        }
    }

    uint32_t frameNumber() const { return event_.frame_number; }

    QList<QVariant> rowData(const QString &station, const QString &bssid,
                            const QString &ssid) const
    {
        return QList<QVariant>()
                << station << bssid << ssid << event_.name << event_.direction
                << event_.result << data(col_time, sort_role).toDouble()
                << data(col_delta, sort_role).toDouble() << event_.frame_number;
    }

private:
    TimelineEvent event_;
};

class ConnectionTreeWidgetItem : public TimelineTreeWidgetItem
{
public:
    ConnectionTreeWidgetItem(QTreeWidget *parent, const TimelineEvent &event,
                             int attempt_number, bool discovery, bool bssid_wide) :
        TimelineTreeWidgetItem(parent, connection_row_type),
        station_(event.station),
        bssid_(event.bssid),
        ssid_(event.ssid),
        attempt_number_(attempt_number),
        event_count_(0),
        first_frame_(event.frame_number),
        last_frame_(event.frame_number),
        first_time_(event.relative_time),
        last_time_(event.relative_time),
        state_(discovery ? ConnectionState::Discovery : ConnectionState::None),
        fast_transition_(false),
        discovery_(discovery),
        bssid_wide_(bssid_wide)
    {
        setText(col_station, station_);
        setText(col_bssid, bssid_);
        setText(col_ssid, ssid_);
        setExpanded(true);
    }

    void addEvent(const TimelineEvent &event)
    {
        double previous_time = event_count_ > 0 ? last_time_ : event.relative_time;
        new TimelineEventTreeWidgetItem(this, event, previous_time);

        if (ssid_.isEmpty() && !event.ssid.isEmpty()) {
            ssid_ = event.ssid;
            setText(col_ssid, ssid_);
        }

        event_count_++;
        last_frame_ = event.frame_number;
        last_time_ = event.relative_time;
        updateState(event);
        updateSummary();
    }

    bool shouldStartNewAttempt(const TimelineEvent &event) const
    {
        if (discovery_ || bssid_wide_ || event.retry ||
            !startsConnectionAttempt(event.type)) {
            return false;
        }

        switch (state_) {
        case ConnectionState::AuthenticationFailed:
        case ConnectionState::AssociationFailed:
        case ConnectionState::Associated:
        case ConnectionState::Connected:
        case ConnectionState::Disconnected:
            return true;
        default:
            return false;
        }
    }

    QString station() const { return station_; }
    QString bssid() const { return bssid_; }
    QString ssid() const { return ssid_; }
    bool isDiscovery() const { return discovery_; }

    QString filterExpression() const
    {
        if (station_.isEmpty() || bssid_.isEmpty()) {
            return QString();
        }
        return QStringLiteral("wlan.addr == %1 && wlan.bssid == %2")
                .arg(station_, bssid_);
    }

    QList<QVariant> rowData() const
    {
        return QList<QVariant>()
                << station_ << bssid_ << ssid_ << text(col_event) << QString()
                << text(col_result) << data(col_time, sort_role).toDouble()
                << data(col_delta, sort_role).toDouble() << text(col_frame);
    }

private:
    void updateState(const TimelineEvent &event)
    {
        switch (event.type) {
        case EventType::ProbeRequest:
        case EventType::ProbeResponse:
            state_ = ConnectionState::Discovery;
            break;
        case EventType::AuthenticationRequest:
            fast_transition_ = fast_transition_ || event.fast_transition;
            state_ = ConnectionState::Authenticating;
            break;
        case EventType::AuthenticationResponse:
            fast_transition_ = fast_transition_ || event.fast_transition;
            if (event.status_code > 0) {
                state_ = ConnectionState::AuthenticationFailed;
                final_detail_ = event.result;
            } else if (event.status_code == 0 && event.authentication_complete) {
                state_ = ConnectionState::Authenticated;
            } else {
                state_ = ConnectionState::Authenticating;
            }
            break;
        case EventType::AssociationRequest:
        case EventType::ReassociationRequest:
            state_ = ConnectionState::Associating;
            break;
        case EventType::AssociationResponse:
        case EventType::ReassociationResponse:
            if (event.status_code > 0) {
                state_ = ConnectionState::AssociationFailed;
                final_detail_ = event.result;
            } else if (event.status_code == 0) {
                state_ = event.type == EventType::ReassociationResponse && fast_transition_
                        ? ConnectionState::Connected : ConnectionState::Associated;
            }
            break;
        case EventType::PairwiseKey:
            state_ = event.key_message == 4 ? ConnectionState::Connected
                                            : ConnectionState::Securing;
            last_key_message_ = event.key_message;
            break;
        case EventType::GroupKey:
            // A group-key exchange does not change pairwise connection state.
            break;
        case EventType::Disassociation:
        case EventType::Deauthentication:
            state_ = ConnectionState::Disconnected;
            final_detail_ = event.result;
            break;
        }
    }

    QString stateSummary() const
    {
        switch (state_) {
        case ConnectionState::Discovery:
            return QObject::tr("Discovery");
        case ConnectionState::Authenticating:
            return QObject::tr("Authentication incomplete");
        case ConnectionState::Authenticated:
            return QObject::tr("Authenticated");
        case ConnectionState::AuthenticationFailed:
            return QObject::tr("Authentication failed: %1").arg(final_detail_);
        case ConnectionState::Associating:
            return QObject::tr("Association incomplete");
        case ConnectionState::Associated:
            return QObject::tr("Associated");
        case ConnectionState::AssociationFailed:
            return QObject::tr("Association failed: %1").arg(final_detail_);
        case ConnectionState::Securing:
            return QObject::tr("4-way handshake incomplete after message %1")
                    .arg(last_key_message_);
        case ConnectionState::Connected:
            return QObject::tr("Connected");
        case ConnectionState::Disconnected:
            return final_detail_.isEmpty() ? QObject::tr("Disconnected")
                                           : QObject::tr("Disconnected: %1").arg(final_detail_);
        case ConnectionState::None:
        default:
            return QObject::tr("Observed");
        }
    }

    void updateSummary()
    {
        QString label;
        if (discovery_) {
            label = QObject::tr("Discovery (%1 events)").arg(event_count_);
        } else if (bssid_wide_) {
            label = QObject::tr("BSSID-wide (%1 events)").arg(event_count_);
        } else {
            label = QObject::tr("Attempt %1 (%2 events)")
                    .arg(attempt_number_).arg(event_count_);
        }
        setText(col_event, label);
        setText(col_result, stateSummary());
        setText(col_time, QString::number(first_time_, 'f', 6));
        setText(col_delta, QString::number((last_time_ - first_time_) * 1000.0, 'f', 3));
        setText(col_frame, first_frame_ == last_frame_
                ? QString::number(first_frame_)
                : QStringLiteral("%1–%2").arg(first_frame_).arg(last_frame_));
        setData(col_time, sort_role, first_time_);
        setData(col_delta, sort_role, (last_time_ - first_time_) * 1000.0);
        setData(col_frame, sort_role, first_frame_);

        switch (state_) {
        case ConnectionState::AuthenticationFailed:
        case ConnectionState::AssociationFailed:
            setIcon(col_result, QApplication::style()->standardIcon(QStyle::SP_MessageBoxCritical));
            break;
        case ConnectionState::Disconnected:
            setIcon(col_result, QApplication::style()->standardIcon(QStyle::SP_MessageBoxWarning));
            break;
        case ConnectionState::Connected:
            setIcon(col_result, QApplication::style()->standardIcon(QStyle::SP_DialogApplyButton));
            break;
        default:
            setIcon(col_result, QApplication::style()->standardIcon(QStyle::SP_MessageBoxInformation));
            break;
        }
    }

    QString station_;
    QString bssid_;
    QString ssid_;
    QString final_detail_;
    int attempt_number_;
    int event_count_;
    uint32_t first_frame_;
    uint32_t last_frame_;
    double first_time_;
    double last_time_;
    ConnectionState state_;
    int last_key_message_ = 0;
    bool fast_transition_;
    bool discovery_;
    bool bssid_wide_;
};

static QString joinDetails(const QStringList &details, bool retry)
{
    QStringList result = details;
    if (retry) {
        result << QObject::tr("Retry");
    }
    return result.join(QStringLiteral(" · "));
}

} // namespace

class WlanConnectionTimelineDialog::Private
{
public:
    Private() :
        hf_auth_algorithm(fieldIdsByName("wlan.fixed.auth.alg")),
        hf_auth_sequence(fieldIdsByName("wlan.fixed.auth_seq")),
        hf_sae_message(fieldIdsByName("wlan.fixed.sae_message_type")),
        hf_status_code(fieldIdsByName("wlan.fixed.status_code")),
        hf_reason_code(fieldIdsByName("wlan.fixed.reason_code")),
        hf_current_ap(fieldIdsByName("wlan.fixed.current_ap")),
        hf_key_message(fieldIdsByName("wlan_rsna_eapol.keydes.msgnr")),
        hf_pairwise_key(fieldIdsByName("wlan_rsna_eapol.keydes.key_info.key_type")),
        hf_replay_counter(fieldIdsByName("eapol.keydes.replay_counter"))
    {
    }

    void rebuildTree(QTreeWidget *tree)
    {
        tree->clear();

        QHash<QString, QString> ssid_by_bssid;
        for (const TimelineEvent &event : events) {
            if (!event.bssid.isEmpty() && !event.ssid.isEmpty() &&
                !event.ssid.startsWith(QLatin1Char('<'))) {
                ssid_by_bssid[event.bssid] = event.ssid;
            }
        }

        QHash<QString, ConnectionTreeWidgetItem *> active_groups;
        QHash<QString, int> attempt_numbers;

        for (TimelineEvent event : events) {
            if (event.ssid.isEmpty()) {
                event.ssid = ssid_by_bssid.value(event.bssid);
            }

            bool discovery = isDiscoveryEvent(event.type);
            bool bssid_wide = event.bssid_wide;
            QString base_key = QStringLiteral("%1\n%2").arg(event.station, event.bssid);
            QString group_key;
            if (discovery) {
                group_key = QStringLiteral("D\n%1\n%2").arg(base_key, event.ssid);
            } else if (bssid_wide) {
                group_key = QStringLiteral("B\n%1").arg(event.bssid);
            } else {
                group_key = QStringLiteral("C\n%1").arg(base_key);
            }
            ConnectionTreeWidgetItem *group = active_groups.value(group_key, nullptr);

            if (group && group->shouldStartNewAttempt(event)) {
                group = nullptr;
            }

            if (!group) {
                int attempt = discovery || bssid_wide
                        ? 0 : attempt_numbers.value(event.station, 0) + 1;
                if (!discovery && !bssid_wide) {
                    attempt_numbers[event.station] = attempt;
                }
                group = new ConnectionTreeWidgetItem(tree, event, attempt, discovery,
                                                     bssid_wide);
                active_groups[group_key] = group;
            }

            group->addEvent(event);
        }
    }

    QVector<TimelineEvent> events;
    QString display_filter;
    FieldIds hf_auth_algorithm;
    FieldIds hf_auth_sequence;
    FieldIds hf_sae_message;
    FieldIds hf_status_code;
    FieldIds hf_reason_code;
    FieldIds hf_current_ap;
    FieldIds hf_key_message;
    FieldIds hf_pairwise_key;
    FieldIds hf_replay_counter;
};

WlanConnectionTimelineDialog::WlanConnectionTimelineDialog(QWidget &parent, CaptureFile &cf,
                                                           const char *filter) :
    TapParameterDialog(parent, cf),
    d_(new Private)
{
    setWindowSubtitle(tr("Wi-Fi Connection Timeline"));
    loadGeometry(parent.width() * 9 / 10, parent.height() * 4 / 5,
                 "WlanConnectionTimelineDialog");
    setHint(tr("Shows 802.11 discovery, authentication, association, key exchange, and disconnect events. Double-click an event to jump to its frame."));

    statsTreeWidget()->setHeaderLabels(QStringList()
            << tr("Station") << tr("BSSID") << tr("SSID") << tr("Event")
            << tr("Direction") << tr("Result / Details") << tr("Time (s)")
            << tr("Δ (ms)") << tr("Frame"));
    statsTreeWidget()->setRootIsDecorated(true);
    statsTreeWidget()->setUniformRowHeights(true);
    statsTreeWidget()->setSelectionBehavior(QAbstractItemView::SelectRows);
    statsTreeWidget()->sortByColumn(col_time, Qt::AscendingOrder);

    for (int column : { col_time, col_delta, col_frame }) {
        statsTreeWidget()->headerItem()->setTextAlignment(column, Qt::AlignRight);
    }

    addFilterActions();
    addTreeCollapseAllActions();

    if (filter) {
        setDisplayFilter(QString::fromUtf8(filter));
        d_->display_filter = QString::fromUtf8(filter);
    }

    connect(this, &TapParameterDialog::updateFilter,
            this, &WlanConnectionTimelineDialog::filterUpdated);
    connect(statsTreeWidget(), &QTreeWidget::itemActivated,
            this, &WlanConnectionTimelineDialog::itemActivated);
}

WlanConnectionTimelineDialog::~WlanConnectionTimelineDialog()
{
    delete d_;
}

void WlanConnectionTimelineDialog::tapReset(void *dialog_ptr)
{
    WlanConnectionTimelineDialog *dialog = static_cast<WlanConnectionTimelineDialog *>(dialog_ptr);
    if (!dialog) {
        return;
    }
    dialog->d_->events.clear();
    dialog->statsTreeWidget()->clear();
}

tap_packet_status WlanConnectionTimelineDialog::tapPacket(void *dialog_ptr,
                                                          packet_info *pinfo,
                                                          epan_dissect *edt,
                                                          const void *wlan_hdr_ptr,
                                                          tap_flags_t)
{
    WlanConnectionTimelineDialog *dialog = static_cast<WlanConnectionTimelineDialog *>(dialog_ptr);
    const wlan_hdr_t *wlan_hdr = static_cast<const wlan_hdr_t *>(wlan_hdr_ptr);
    if (!dialog || !pinfo || !edt || !wlan_hdr) {
        return TAP_PACKET_DONT_REDRAW;
    }

    Private *d = dialog->d_;
    uint32_t key_message = 0;
    bool is_key_event = fieldUnsigned(edt, d->hf_key_message, key_message);
    uint16_t subtype = wlan_hdr->type;
    uint32_t auth_sequence = 0;
    bool has_auth_sequence = subtype == MGT_AUTHENTICATION &&
            fieldUnsigned(edt, d->hf_auth_sequence, auth_sequence);
    bool source_is_ap = addresses_data_equal(&wlan_hdr->src, &wlan_hdr->bssid);
    bool destination_is_ap = addresses_data_equal(&wlan_hdr->dst, &wlan_hdr->bssid);

    EventType event_type;
    if (is_key_event) {
        uint64_t pairwise = 1;
        fieldUnsigned64(edt, d->hf_pairwise_key, pairwise);
        event_type = pairwise ? EventType::PairwiseKey : EventType::GroupKey;
    } else {
        switch (subtype) {
        case MGT_PROBE_REQ:
            event_type = EventType::ProbeRequest;
            break;
        case MGT_PROBE_RESP:
            event_type = EventType::ProbeResponse;
            break;
        case MGT_AUTHENTICATION:
            if (source_is_ap) {
                event_type = EventType::AuthenticationResponse;
            } else if (destination_is_ap) {
                event_type = EventType::AuthenticationRequest;
            } else if (has_auth_sequence) {
                event_type = (auth_sequence & 1) ? EventType::AuthenticationRequest
                                                 : EventType::AuthenticationResponse;
            } else {
                event_type = EventType::AuthenticationRequest;
            }
            break;
        case MGT_ASSOC_REQ:
            event_type = EventType::AssociationRequest;
            break;
        case MGT_ASSOC_RESP:
            event_type = EventType::AssociationResponse;
            break;
        case MGT_REASSOC_REQ:
            event_type = EventType::ReassociationRequest;
            break;
        case MGT_REASSOC_RESP:
            event_type = EventType::ReassociationResponse;
            break;
        case MGT_DISASS:
            event_type = EventType::Disassociation;
            break;
        case MGT_DEAUTHENTICATION:
            event_type = EventType::Deauthentication;
            break;
        default:
            return TAP_PACKET_DONT_REDRAW;
        }
    }

    const address *station_address = nullptr;

    if (source_is_ap) {
        station_address = &wlan_hdr->dst;
    } else if (destination_is_ap) {
        station_address = &wlan_hdr->src;
    } else {
        switch (event_type) {
        case EventType::ProbeResponse:
        case EventType::AssociationResponse:
        case EventType::ReassociationResponse:
        case EventType::AuthenticationResponse:
            station_address = &wlan_hdr->dst;
            break;
        case EventType::PairwiseKey:
        case EventType::GroupKey:
            station_address = (key_message & 1) ? &wlan_hdr->dst : &wlan_hdr->src;
            break;
        default:
            station_address = &wlan_hdr->src;
            break;
        }
    }

    if (!station_address) {
        return TAP_PACKET_DONT_REDRAW;
    }

    TimelineEvent event;
    event.type = event_type;
    event.frame_number = pinfo->num;
    event.relative_time = nstime_to_sec(&pinfo->rel_ts);
    event.station = address_to_qstring(station_address);
    event.bssid = address_to_qstring(&wlan_hdr->bssid);
    event.ssid = ssidFromHeader(wlan_hdr);
    event.retry = wlan_hdr->stats.fc_retry;
    event.key_message = is_key_event ? static_cast<int>(key_message) : -1;
    event.bssid_wide = isBroadcastWlanAddress(station_address);

    if (event.type == EventType::ProbeRequest && event.ssid.isEmpty()) {
        event.ssid = tr("<Wildcard>");
    }

    if (event.bssid_wide && source_is_ap) {
        event.direction = tr("AP → Broadcast");
    } else if (event.type == EventType::ProbeRequest &&
               is_broadcast_bssid(&wlan_hdr->bssid)) {
        event.direction = tr("STA → Broadcast");
    } else if (source_is_ap) {
        event.direction = tr("AP → STA");
    } else if (destination_is_ap) {
        event.direction = tr("STA → AP");
    } else {
        switch (event.type) {
        case EventType::ProbeResponse:
        case EventType::AuthenticationResponse:
        case EventType::AssociationResponse:
        case EventType::ReassociationResponse:
            event.direction = tr("AP → STA");
            break;
        case EventType::ProbeRequest:
        case EventType::AuthenticationRequest:
        case EventType::AssociationRequest:
        case EventType::ReassociationRequest:
            event.direction = tr("STA → AP");
            break;
        case EventType::PairwiseKey:
        case EventType::GroupKey:
            event.direction = (key_message & 1) ? tr("AP → STA") : tr("STA → AP");
            break;
        default:
            event.direction = address_to_qstring(&wlan_hdr->src) +
                    QStringLiteral(" → ") + address_to_qstring(&wlan_hdr->dst);
            break;
        }
    }

    QStringList details;
    uint32_t value = 0;
    switch (event.type) {
    case EventType::ProbeRequest:
        event.name = tr("Probe request");
        break;
    case EventType::ProbeResponse:
        event.name = tr("Probe response");
        break;
    case EventType::AuthenticationRequest:
    case EventType::AuthenticationResponse:
        event.name = event.type == EventType::AuthenticationRequest
                ? tr("Authentication request") : tr("Authentication response");
        if (has_auth_sequence) {
            details << tr("Sequence %1").arg(auth_sequence);
        }
        {
            uint32_t auth_algorithm = 0;
            if (fieldUnsigned(edt, d->hf_auth_algorithm, auth_algorithm)) {
                event.fast_transition =
                        auth_algorithm == auth_algorithm_fast_bss_transition;
                if (auth_algorithm == auth_algorithm_shared_key) {
                    event.authentication_complete = has_auth_sequence && auth_sequence >= 4;
                }
            }
            QString algorithm = fieldDisplay(edt, d->hf_auth_algorithm);
            if (!algorithm.isEmpty()) {
                details << algorithm;
            }
            uint32_t sae_message_type = 0;
            QString sae_message;
            if (fieldUnsigned(edt, d->hf_sae_message, sae_message_type)) {
                event.authentication_complete = sae_message_type != sae_message_commit;
                sae_message = fieldDisplay(edt, d->hf_sae_message);
            }
            if (!sae_message.isEmpty()) {
                details << tr("SAE %1").arg(sae_message);
            }
        }
        if (event.type == EventType::AuthenticationResponse &&
            fieldUnsigned(edt, d->hf_status_code, value)) {
            event.status_code = static_cast<int>(value);
            if (value == status_sae_anti_clogging_token_required ||
                value == status_sae_hash_to_element) {
                event.status_code = -1;
                event.authentication_complete = false;
            }
            QString status = fieldDisplay(edt, d->hf_status_code);
            details.prepend(value == 0 ? tr("Success")
                                      : tr("Status %1: %2").arg(value).arg(status));
        }
        break;
    case EventType::AssociationRequest:
        event.name = tr("Association request");
        break;
    case EventType::AssociationResponse:
        event.name = tr("Association response");
        if (fieldUnsigned(edt, d->hf_status_code, value)) {
            event.status_code = static_cast<int>(value);
            QString status = fieldDisplay(edt, d->hf_status_code);
            details << (value == 0 ? tr("Success")
                                   : tr("Status %1: %2").arg(value).arg(status));
        }
        break;
    case EventType::ReassociationRequest:
        event.name = tr("Reassociation request");
        {
            QString current_ap = fieldDisplay(edt, d->hf_current_ap);
            if (!current_ap.isEmpty()) {
                details << tr("Previous AP %1").arg(current_ap);
            }
        }
        break;
    case EventType::ReassociationResponse:
        event.name = tr("Reassociation response");
        if (fieldUnsigned(edt, d->hf_status_code, value)) {
            event.status_code = static_cast<int>(value);
            QString status = fieldDisplay(edt, d->hf_status_code);
            details << (value == 0 ? tr("Success")
                                   : tr("Status %1: %2").arg(value).arg(status));
        }
        break;
    case EventType::PairwiseKey:
    case EventType::GroupKey:
        event.name = event.type == EventType::PairwiseKey
                ? tr("4-way handshake message %1 of 4").arg(key_message)
                : tr("Group-key handshake message %1 of 2").arg(key_message);
        {
            uint64_t replay_counter = 0;
            if (fieldUnsigned64(edt, d->hf_replay_counter, replay_counter)) {
                details << tr("Replay counter %1").arg(replay_counter);
            }
        }
        break;
    case EventType::Disassociation:
    case EventType::Deauthentication:
        event.name = event.type == EventType::Disassociation
                ? tr("Disassociation") : tr("Deauthentication");
        if (fieldUnsigned(edt, d->hf_reason_code, value)) {
            QString reason = fieldDisplay(edt, d->hf_reason_code);
            details << tr("Reason %1: %2").arg(value).arg(reason);
        }
        break;
    }

    event.result = joinDetails(details, event.retry);
    d->events.append(event);
    return TAP_PACKET_REDRAW;
}

void WlanConnectionTimelineDialog::tapDraw(void *dialog_ptr)
{
    WlanConnectionTimelineDialog *dialog = static_cast<WlanConnectionTimelineDialog *>(dialog_ptr);
    if (!dialog) {
        return;
    }
    dialog->d_->rebuildTree(dialog->statsTreeWidget());
}

void WlanConnectionTimelineDialog::fillTree()
{
    static const QString milestone_filter = QStringLiteral(
            "wlan.fc.type_subtype in {0x0000,0x0001,0x0002,0x0003,0x0004,0x0005,0x000a,0x000b,0x000c} || "
            "wlan.fixed.auth.alg || wlan.fixed.auth_seq || wlan.fixed.sae_message_type || "
            "wlan.fixed.status_code || wlan.fixed.reason_code || wlan.fixed.current_ap || "
            "wlan_rsna_eapol.keydes.msgnr || wlan_rsna_eapol.keydes.key_info.key_type || "
            "eapol.keydes.replay_counter");

    QString tap_filter = milestone_filter;
    if (!d_->display_filter.isEmpty()) {
        tap_filter = QStringLiteral("(%1) && (%2)").arg(milestone_filter, d_->display_filter);
    }
    QByteArray tap_filter_utf8 = tap_filter.toUtf8();

    if (!registerTapListener("wlan", this, tap_filter_utf8.constData(),
                             TL_REQUIRES_PROTO_TREE, tapReset, tapPacket, tapDraw)) {
        reject();
        return;
    }

    statsTreeWidget()->setSortingEnabled(false);
    cap_file_.retapPackets();
    tapDraw(this);
    removeTapListeners();
    statsTreeWidget()->setSortingEnabled(true);
    statsTreeWidget()->sortItems(col_time, Qt::AscendingOrder);
    drawTreeItems();
}

const QString WlanConnectionTimelineDialog::filterExpression()
{
    QList<QTreeWidgetItem *> selected = statsTreeWidget()->selectedItems();
    if (selected.isEmpty()) {
        return QString();
    }

    if (TimelineEventTreeWidgetItem *event_item =
            dynamic_cast<TimelineEventTreeWidgetItem *>(selected.first())) {
        return QStringLiteral("frame.number == %1").arg(event_item->frameNumber());
    }
    if (ConnectionTreeWidgetItem *connection_item =
            dynamic_cast<ConnectionTreeWidgetItem *>(selected.first())) {
        return connection_item->filterExpression();
    }
    return QString();
}

QList<QVariant> WlanConnectionTimelineDialog::treeItemData(QTreeWidgetItem *item) const
{
    if (ConnectionTreeWidgetItem *connection_item =
            dynamic_cast<ConnectionTreeWidgetItem *>(item)) {
        return connection_item->rowData();
    }
    if (TimelineEventTreeWidgetItem *event_item =
            dynamic_cast<TimelineEventTreeWidgetItem *>(item)) {
        ConnectionTreeWidgetItem *parent_item =
                dynamic_cast<ConnectionTreeWidgetItem *>(item->parent());
        if (parent_item) {
            return event_item->rowData(parent_item->station(), parent_item->bssid(),
                                       parent_item->ssid());
        }
    }
    return QList<QVariant>();
}

void WlanConnectionTimelineDialog::captureFileClosing()
{
    removeTapListeners();
    WiresharkDialog::captureFileClosing();
}

void WlanConnectionTimelineDialog::filterUpdated(const QString &filter)
{
    d_->display_filter = filter;
}

void WlanConnectionTimelineDialog::itemActivated(QTreeWidgetItem *item, int)
{
    TimelineEventTreeWidgetItem *event_item =
            dynamic_cast<TimelineEventTreeWidgetItem *>(item);
    if (event_item) {
        mainApp->gotoFrame(event_item->frameNumber());
    }
}

// Stat command + args

static bool wlan_connection_timeline_init(const char *args, void *)
{
    QStringList arguments = QString::fromUtf8(args).split(QLatin1Char(','));
    QByteArray filter;
    if (arguments.length() > 2) {
        filter = QStringList(arguments.mid(2)).join(QLatin1Char(',')).toUtf8();
    }
    mainApp->emitStatCommandSignal("WlanConnectionTimeline", filter.constData(), nullptr);
    return true;
}

static stat_tap_ui wlan_connection_timeline_ui = {
    REGISTER_STAT_GROUP_GENERIC,
    nullptr,
    "wlan,connection",
    wlan_connection_timeline_init,
    0,
    nullptr
};

extern "C" {

void register_tap_listener_qt_wlan_connection_timeline(void);

void register_tap_listener_qt_wlan_connection_timeline(void)
{
    register_stat_tap_ui(&wlan_connection_timeline_ui, nullptr);
}

}
