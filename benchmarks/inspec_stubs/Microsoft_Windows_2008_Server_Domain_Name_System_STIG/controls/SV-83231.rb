control 'SV-83231' do
  title 'The Windows 2008 DNS Server must be configured to record, and make available to authorized personnel, who added/modified/deleted DNS zone information.'
  desc 'Without a means for identifying the individual that produced the information, the information cannot be relied upon. Identifying the validity of information may be delayed or deterred.

This requirement ensures organizational personnel have a means to identify who produced or changed specific information in transfers, zone information, or DNS configuration changes.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account.

Press Windows Key + R, execute dnsmgmt.msc.

Right-click the DNS server, select “Properties”.

Click on the “Event Logging” tab. By default, all events are logged.

Verify "Errors and warnings" or "All events" is selected.

If any option other than "Errors and warnings" or "All events" is selected, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account.

If not automatically started, initialize the “Server Manager” window by clicking its icon from the bottom left corner of the screen.

On the opened “Server Manager” window, from the left pane, click to select “DNS”.

From the right pane, under the “SERVERS” section, right-click the DNS server.

From the displayed context menu, click the “DNS Manager” option.

Click on the “Event Logging” tab.

Select the "Errors and warnings" or "All events" option.

Click on “Apply”.

Click on “OK”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 DNS'
  ref 'DPMS Target Windows 2008 R2 DNS'
  tag check_id: 'C-59415r3_chk'
  tag severity: 'medium'
  tag gid: 'V-58543'
  tag rid: 'SV-83231r1_rule'
  tag stig_id: 'WDNS-AU-000001'
  tag gtitle: 'SRG-APP-000348-DNS-000042'
  tag fix_id: 'F-63927r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001902']
  tag nist: ['CM-6 b', 'AU-10 (1) (b)']
end
