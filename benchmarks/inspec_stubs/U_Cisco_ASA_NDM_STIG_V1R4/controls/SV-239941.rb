control 'SV-239941' do
  title 'The Cisco ASA must be configured to conduct backups of system-level information contained in the information system when changes occur.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Review the Cisco ASA configuration to verify it is compliant with this requirement. The example configuration below will send the configuration to an SCP server when a configuration change occurs.

event manager applet BACKUP_CONFIG
  event syslog pattern "SYSLOG_CONFIG_I"
  action 1 cli command "copy startup-config scp://userx:xxxxxxx@10.1.48.10//opt/config_backup" 
  action 2 syslog priority informational msg "Configuration backup was executed"

Note: Tools such as Cisco Security Manager, Cisco Prime Infrastructure, Firemon, or Tripwire can be used to back up the configuration.

If the Cisco ASA is not configured to conduct backups of the configuration when changes occur, this is a finding.'
  desc 'fix', 'Configure the Cisco ASA to send the configuration to an SCP server when a configuration change occurs as shown in the example below.

ASA(config)# event manager applet BACKUP_CONFIG
ASA(config-applet)# event syslog pattern "SYSLOG_CONFIG_I"
ASA(config-applet)# action 1 cli command " copy startup-config scp://userx:xxxxxxx@10.1.48.10//opt/config_backup”
ASA(config-applet)# action 2 syslog priority informational msg "Configuration backup was executed"
ASA(config-applet)# end'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43174r666184_chk'
  tag severity: 'medium'
  tag gid: 'V-239941'
  tag rid: 'SV-239941r879887_rule'
  tag stig_id: 'CASA-ND-001350'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-43133r666185_fix'
  tag 'documentable'
  tag cci: ['CCI-000537']
  tag nist: ['CP-9 (b)']
end
