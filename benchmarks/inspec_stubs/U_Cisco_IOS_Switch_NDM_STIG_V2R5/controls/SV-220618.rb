control 'SV-220618' do
  title 'The Cisco switch must be configured to support organizational requirements to conduct backups of the configuration when changes occur.'
  desc 'System-level information includes default and customized settings and security attributes, including access control lists (ACLs) that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial-of-service condition is possible for all who use this critical network component.

The network device must support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Review the Cisco switch configuration to verify that it backs up the configuration when changes occur. The example configuration below will send the configuration to a TFTP server when a configuration change occurs:

event manager applet BACKUP_CONFIG
 event syslog pattern "%SYS-5-CONFIG_I"
 action 1 info type switchname
 action 2 cli command "enable"
 action 3 cli command "copy run tftp" pattern "remote host"
 action 4 cli command "x.x.x.x" pattern "filename"
 action 5 cli command "$_info_switchname-config"
 action 6 syslog priority informational msg "Configuration backup was executed"

If the Cisco switch is not configured to conduct backups of the configuration when changes occur, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to send the configuration to a TFTP or an FTP server when a configuration change occurs as shown in the example below:

SW4(config)#event manager applet BACKUP_CONFIG
SW4(config-applet)#event syslog pattern "%SYS-5-CONFIG_I"
SW4(config-applet)#action 1 cli command "enable"
SW4(config-applet)#action 2 info type switchname
SW4(config-applet)#action 3 cli command "copy run tftp" pattern "remote host"
SW4(config-applet)#action 4 cli command "x.x.x.x" pattern "filename"
SW4(config-applet)#action 5 cli command "$_info_switchname-config"
SW4(config-applet)#action 6 syslog priority informational msg "Configuration backup was executed"
SW4(config-applet)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22333r507900_chk'
  tag severity: 'medium'
  tag gid: 'V-220618'
  tag rid: 'SV-220618r879887_rule'
  tag stig_id: 'CISC-ND-001410'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-22322r507901_fix'
  tag 'documentable'
  tag legacy: ['SV-110465', 'V-101361']
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
