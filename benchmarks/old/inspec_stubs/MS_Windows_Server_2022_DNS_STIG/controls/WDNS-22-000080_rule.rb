control 'WDNS-22-000080_rule' do
  title 'The Windows 2022 DNS Server must log the event and notify the system administrator when anomalies in the operation of the signed zone transfers are discovered.'
  desc 'Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes but is not limited to establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. Notifications provided by information systems include messages to local computer consoles and/or hardware indications, such as lights.

If anomalies are not acted on, security functions may fail to secure the system.

The DNS server does not have the capability of shutting down or restarting the information system. The DNS server can be configured to generate audit records when anomalies are discovered, and the operating system/network device manager can then trigger notification messages to the system administrator based on the presence of those audit records.'
  desc 'check', 'Note: If the only zones hosted are AD-integrated zones, this check is not applicable.

Notification to the system administrator is not configurable in Windows 2022. For the administrator to be notified if functionality of DNSSEC/TSIG has been removed or broken, the information system security officer (ISSO), information system security manager (ISSM), or DNS administrator would need to implement a third-party monitoring system. At a minimum, the ISSO/ISSM/DNS administrator should have a documented procedure in place to review the diagnostic logs on a routine basis every day.

If a third-party monitoring system is not in place to detect and notify the ISSO/ISSM/DNS administrator if functionality of DNSSEC/TSIG has been removed or broken and the ISSO/ISSM/DNS administrator does not have a documented procedure in place to review the diagnostic logs on a routine basis every day, this is a finding.'
  desc 'fix', 'Implement a third-party monitoring system to detect and notify the ISSO/ISSM/DNS administrator if functionality of DNSSEC/TSIG has been removed or broken or, at a minimum, document and implement a procedure to review the diagnostic logs on a routine basis every day.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000080_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000080'
  tag rid: 'WDNS-22-000080_rule'
  tag stig_id: 'WDNS-22-000080'
  tag gtitle: 'SRG-APP-000474-DNS-000073'
  tag fix_id: 'F-WDNS-22-000080_fix'
  tag 'documentable'
  tag cci: ['CCI-002702']
  tag nist: ['SI-6 d']
end
