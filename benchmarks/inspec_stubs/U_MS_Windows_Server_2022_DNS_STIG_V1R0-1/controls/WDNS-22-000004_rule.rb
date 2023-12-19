control 'WDNS-22-000004_rule' do
  title 'The Windows 2022 DNS Server log must be enabled.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. The actual auditing is performed by the operating system/network device manager, but the configuration to trigger the auditing is controlled by the DNS server.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

Right-click the DNS server and select "Properties".

Click the "Event Logging" tab. By default, all events are logged.

Verify "Errors and warnings" or "All events" is selected.

If any option other than "Errors and warnings" or "All events" is selected, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press the Windows key + R and execute "dnsmgmt.msc".

Right-click the DNS server and select "Properties".

Click the "Event Logging" tab. By default, all events are logged.

Select the "Errors and warnings" or "All events" option.

Click "Apply".

Click "OK".'
  impact 0.5
  tag check_id: 'C-WDNS-22-000004_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000004'
  tag rid: 'WDNS-22-000004_rule'
  tag stig_id: 'WDNS-22-000004'
  tag gtitle: 'SRG-APP-000089-DNS-000004'
  tag fix_id: 'F-WDNS-22-000004_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
