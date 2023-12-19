control 'SV-215650' do
  title 'The Windows 2012 DNS Server log must be enabled.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. The actual auditing is performed by the OS/NDM, but the configuration to trigger the auditing is controlled by the DNS server.'
  desc 'check', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

Right-click the DNS server, select “Properties”.

Click on the “Event Logging” tab. By default, all events are logged.

Verify "Errors and warnings" or "All events" is selected.

If any option other than "Errors and warnings" or "All events" is selected, this is a finding.'
  desc 'fix', 'Log on to the DNS server using the Domain Admin or Enterprise Admin account or Local Administrator account.

Press Windows Key + R, execute dnsmgmt.msc.

Right-click the DNS server, select “Properties”.

Click on the “Event Logging” tab. By default, all events are logged.

Select the "Errors and warnings" or "All events" option.

Click on “Apply”.

Click “OK”.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16844r572168_chk'
  tag severity: 'medium'
  tag gid: 'V-215650'
  tag rid: 'SV-215650r561297_rule'
  tag stig_id: 'WDNS-AU-000005'
  tag gtitle: 'SRG-APP-000089-DNS-000004'
  tag fix_id: 'F-16842r572169_fix'
  tag 'documentable'
  tag legacy: ['V-58549', 'SV-72979']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
