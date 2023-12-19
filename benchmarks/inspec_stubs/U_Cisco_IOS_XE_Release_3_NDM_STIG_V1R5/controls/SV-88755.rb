control 'SV-88755' do
  title 'The Cisco IOS XE router must support organizational requirements to conduct backups of system level information contained in the information system when changes occur or weekly, whichever is sooner.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Verify that the Cisco IOS XE router has the event manager configured to do automated backups.

The configuration should look similar to the example below:

event manager applet backup-config
 event timer watchdog time 86400
 action 1.0 cli command "enable"
 action 2.0 info type routername
 action 3.0 cli command "copy runn tftp://x.x.x.x/$_info_routername.cfg" pattern "Address"
 action 4.0 cli command "" pattern "Destination"
 action 5.0 cli command ""

If the event manager is not configured for automated backups, this is a finding.'
  desc 'fix', 'Configure the event manager for automated backups.

The configuration should look similar to the example below:

event manager applet backup-config
 event timer watchdog time 86400
 action 1.0 cli command "enable"
 action 2.0 info type routername
 action 3.0 cli command "copy runn tftp://x.x.x.x/$_info_routername.cfg" pattern "Address"
 action 4.0 cli command "" pattern "Destination"
 action 5.0 cli command ""'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74173r3_chk'
  tag severity: 'low'
  tag gid: 'V-74081'
  tag rid: 'SV-88755r2_rule'
  tag stig_id: 'CISR-ND-000138'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-80621r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
