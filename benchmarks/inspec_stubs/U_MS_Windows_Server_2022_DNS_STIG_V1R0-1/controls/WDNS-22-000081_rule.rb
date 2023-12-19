control 'WDNS-22-000081_rule' do
  title 'The Windows 2022 DNS Server must be configured to notify the information system security officer (ISSO), information system security manager (ISSM), or DNS administrator when functionality of DNSSEC/TSIG has been removed or broken.'
  desc 'Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes but is not limited to establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters. If personnel are not notified of failed security verification tests, they will not be able to take corrective action, and the unsecure condition(s) will remain. Notifications provided by information systems include messages to local computer consoles and/or hardware indications, such as lights.

The DNS server should be configured to generate audit records whenever a self-test fails. The operating system/network device manager is responsible for generating notification messages related to this audit record.'
  desc 'check', 'Note: This check is not applicable for Windows 2022 DNS Servers that only host Active Directory-integrated zones or for Windows 2022 DNS servers on a classified network.

Notification to the system administrator is not configurable in Windows DNS Server. For the ISSO/ISSM/DNS administrator to be notified if functionality of Secure Updates has been removed or broken, the ISSO/ISSM/DNS administrator would need to implement a third party monitoring system. At a minimum, the ISSO/ISSM/DNS administrator should have a documented procedure in place to review the diagnostic logs on a routine basis every day.

If a third-party monitoring system is not in place to detect and notify the ISSO/ISSM/DNS administrator if functionality of Secure Updates has been removed or broken and the ISSO/ISSM/DNS administrator does not have a documented procedure in place to review the diagnostic logs on a routine basis every day, this is a finding.'
  desc 'fix', 'Implement a third-party monitoring system to detect and notify the ISSO/ISSM/DNS administrator if functionality of Secure Updates has been removed or broken or, at a minimum, document and implement a procedure to review the diagnostic logs on a routine basis every day.'
  impact 0.5
  tag check_id: 'C-WDNS-22-000081_chk'
  tag severity: 'medium'
  tag gid: 'WDNS-22-000081'
  tag rid: 'WDNS-22-000081_rule'
  tag stig_id: 'WDNS-22-000081'
  tag gtitle: 'SRG-APP-000275-DNS-000040'
  tag fix_id: 'F-WDNS-22-000081_fix'
  tag 'documentable'
  tag cci: ['CCI-001294']
  tag nist: ['SI-6 c']
end
