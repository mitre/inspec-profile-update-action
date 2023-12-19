control 'WDNS-22-000002_rule' do
  title 'The Windows 2022 DNS Server must be configured to record who added/modified/deleted DNS zone information.'
  desc 'Without a means for identifying the individual that produced the information, the information cannot be relied on. Identifying the validity of information may be delayed or deterred.

This requirement ensures organizational personnel have a means to identify who produced or changed specific information in transfers, zone information, or DNS configuration changes.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

Right-click the DNS server and select "Properties".

Click the "Event Logging" tab. By default, all events are logged.

Verify "Errors and warnings" or "All events" is selected.

If any option other than "Errors and warnings" or "All events" is selected, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

If not automatically started, initialize the "Server Manager" window by clicking its icon from the bottom left corner of the screen.

On the opened "Server Manager" window, from the left pane, click to select "DNS".

From the right pane, under the "SERVERS" section, right-click the DNS server.

From the displayed context menu, click the "DNS Manager" option.

Click the "Event Logging" tab.

Select the "Errors and warnings" or "All events" option.

Click "Apply".

Click "OK".'
  impact 0.5
  tag check_id: 'C-WDNS-22-000002_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000002'
  tag rid: 'WDNS-22-000002_rule'
  tag stig_id: 'WDNS-22-000002'
  tag gtitle: 'SRG-APP-000348-DNS-000042'
  tag fix_id: 'F-WDNS-22-000002_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001902']
  tag nist: ['CM-6 b', 'AU-10 (1) (b)']
end
