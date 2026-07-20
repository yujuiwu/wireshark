/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef WLAN_BLOCK_ACK_GRAPH_DIALOG_H
#define WLAN_BLOCK_ACK_GRAPH_DIALOG_H

#include "wireshark_dialog.h"

class QCPAbstractPlottable;
class QMouseEvent;

class WlanBlockAckGraphDialog : public WiresharkDialog
{
    Q_OBJECT

public:
    explicit WlanBlockAckGraphDialog(QWidget &parent, CaptureFile &cf);
    ~WlanBlockAckGraphDialog();

signals:
    void goToPacket(int packet_num);

protected:
    void captureFileClosing() override;

private:
    class Private;
    Private *const d_;

    static void tapReset(void *dialog_ptr);
    static tap_packet_status tapPacket(void *dialog_ptr, struct _packet_info *pinfo,
                                      struct epan_dissect *edt, const void *wlan_hdr_ptr,
                                      tap_flags_t flags);
    static void tapDraw(void *dialog_ptr);

    void collectBlockAcks();
    void populateSessions();
    void populateTids(int preferred_session = -1, int preferred_tid = -1);
    int currentSessionIndex() const;
    void drawSession();
    void clearTimeDeltaLabels();
    void drawTimeDeltaLabels();
    void showSampleDetails(int data_index);
    void showRequestDetails(int data_index);
    int anchorIndexForPlottable(QCPAbstractPlottable *plottable, int data_index) const;
    void zoomXAxis(bool in);
    void zoomYAxis(bool in);

private slots:
    void stationPairChanged(int pair_index);
    void tidChanged(int tid_index);
    void ssnLabelsToggled(bool checked);
    void timeDeltasToggled(bool checked);
    void bitmapHolesToggled(bool checked);
    void plotClicked(QCPAbstractPlottable *plottable, int data_index, QMouseEvent *event);
    void resetAxes();
    void saveGraph();
};

#endif // WLAN_BLOCK_ACK_GRAPH_DIALOG_H
