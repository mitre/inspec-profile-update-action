control 'SV-216545' do
  title 'The Cisco router must be configured to back up the configuration when changes occur.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement. The example configuration below will send the configuration to an TFTP server when a configuration change occurs.

configuration commit auto-save filename tftp://10.1.3.18

If the Cisco router is not configured to conduct backups of the configuration when changes occur, this is a finding.'
  desc 'fix', 'Configure the Cisco router to send the configuration to an TFTP or FTP server when a configuration change occurs as shown in the example below.

RP/0/0/CPU0:R3(config)#configuration commit auto-save filename tftp:// 10.1.3.18'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17780r288321_chk'
  tag severity: 'medium'
  tag gid: 'V-216545'
  tag rid: 'SV-216545r531088_rule'
  tag stig_id: 'CISC-ND-001410'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-17777r288322_fix'
  tag 'documentable'
  tag legacy: ['SV-105629', 'V-96491']
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
