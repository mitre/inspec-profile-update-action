control 'SV-255964' do
  title 'The network device must be configured to conduct backups of system level information contained in the information system when changes occur.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Verify the Arista network device is configured with an “event-handler” to complete an incremental backup of the running configuration, which can be maintained in the switch flash memory stored in /mnt/flash/startup-config_directory (filetime):

switch#show run | section event-handler
event-handler CFG_BACKUP
   trigger on-startup-config
   action bash buf () { filetime=$(date +%Y%m%d); cp /mnt/flash/startup-config /mnt/flash/startup-config_${filetime}; }; buf
!

If the Arista network device is not configured to conduct backups of system-level data when changes occur, this is a finding.'
  desc 'fix', 'Configure the Arista network device with an “event-handler” to complete an incremental backup of the running configuration, which can be maintained in the switch flash memory stored in /mnt/flash/startup-config_directory (filetime):

switch#config
switch(config)#event-handler CFG_BACKUP
switch(config-handler-CFG_BACKUP)#trigger on-startup-config
switch(config-handler-CFG_BACKUP)#action bash buf () { filetime=$(date +%Y%m%d); cp /mnt/flash/startup-config /mnt/flash/startup-config_${filetime}; }; buf
switch(config-handler-CFG_BACKUP)#exit
switch(config)#exit
!'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x NDM'
  tag check_id: 'C-59640r882232_chk'
  tag severity: 'medium'
  tag gid: 'V-255964'
  tag rid: 'SV-255964r882234_rule'
  tag stig_id: 'ARST-ND-000820'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-59583r882233_fix'
  tag 'documentable'
  tag cci: ['CCI-000537']
  tag nist: ['CP-9 (b)']
end
