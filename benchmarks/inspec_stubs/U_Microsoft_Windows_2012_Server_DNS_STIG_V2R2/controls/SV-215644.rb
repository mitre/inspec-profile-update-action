control 'SV-215644' do
  title 'The Windows 2012 DNS Server must log the event and notify the system administrator when anomalies in the operation of the signed zone transfers are discovered.'
  desc 'Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. Notifications provided by information systems include messages to local computer consoles, and/or hardware indications, such as lights.

If anomalies are not acted upon, security functions may fail to secure the system.

The DNS server does not have the capability of shutting down or restarting the information system. The DNS server can be configured to generate audit records when anomalies are discovered, and the OS/NDM can then trigger notification messages to the system administrator based on the presence of those audit records.'
  desc 'check', 'Note: If only zones hosted are AD-integrated zones, this check is not applicable.

Notification to system administrator is not configurable in Windows 2012. In order for administrator to be notified if functionality of DNSSEC/TSIG has been removed or broken, the ISSO/ISSM/DNS administrator would need to implement a third-party monitoring system. At a minimum, the ISSO/ISSM/DNS administrator should have a documented procedure in place to review the diagnostic logs on a routine basis every day.

If a third-party monitoring system is not in place to detect and notify the ISSO/ISSM/DNS administrator if functionality of DNSSEC/TSIG has been removed or broken and the ISSO/ISSM/DNS administrator does not have a documented procedure in place to review the diagnostic logs on a routine basis every day, this is a finding.'
  desc 'fix', 'Implement a third-party monitoring system to detect and notify the ISSO/ISSM/DNS administrator if functionality of DNSSEC/TSIG has been removed or broken or, at a minimum, document and implement a procedure to review the diagnostic logs on a routine basis every day.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 2012 Server Domain Name System'
  tag check_id: 'C-16838r495403_chk'
  tag severity: 'medium'
  tag gid: 'V-215644'
  tag rid: 'SV-215644r561297_rule'
  tag stig_id: 'WDNS-SI-000007'
  tag gtitle: 'SRG-APP-000474-DNS-000073'
  tag fix_id: 'F-16836r314408_fix'
  tag 'documentable'
  tag legacy: ['SV-73145', 'V-58715']
  tag cci: ['CCI-002699']
  tag nist: ['SI-6 b']
end
