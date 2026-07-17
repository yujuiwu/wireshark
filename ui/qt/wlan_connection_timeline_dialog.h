/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WLAN_CONNECTION_TIMELINE_DIALOG_H
#define WLAN_CONNECTION_TIMELINE_DIALOG_H

#include "tap_parameter_dialog.h"

class QTreeWidgetItem;

class WlanConnectionTimelineDialog : public TapParameterDialog
{
    Q_OBJECT

public:
    WlanConnectionTimelineDialog(QWidget &parent, CaptureFile &cf, const char *filter);
    ~WlanConnectionTimelineDialog();

protected:
    void captureFileClosing() override;

private:
    class Private;
    Private *const d_;

    // Callbacks for register_tap_listener
    static void tapReset(void *dialog_ptr);
    static tap_packet_status tapPacket(void *dialog_ptr, struct _packet_info *pinfo,
                                      struct epan_dissect *edt, const void *wlan_hdr_ptr,
                                      tap_flags_t flags);
    static void tapDraw(void *dialog_ptr);

    const QString filterExpression() override;
    QList<QVariant> treeItemData(QTreeWidgetItem *item) const override;

private slots:
    void fillTree() override;
    void filterUpdated(const QString &filter);
    void itemActivated(QTreeWidgetItem *item, int column);
};

#endif // WLAN_CONNECTION_TIMELINE_DIALOG_H
