control 'SV-79673' do
  title 'The DataPower Gateway must support organizational requirements to conduct backups of system level information contained in the information system when changes occur or weekly, whichever is sooner.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Go to Administration >> Main >> System Control. Verify Secure Backup. If it is not configured, this is a finding.'
  desc 'fix', 'Go to Administration >> Main >> System Control and configure Secure Backup. Go to Administration >> Configuration >> Export Configuration to do the backup. This can be automated via external scripting or Scheduled Rule - XML Manager in default domain.'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65811r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65183'
  tag rid: 'SV-79673r1_rule'
  tag stig_id: 'WSDP-NM-000138'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-71123r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
