control 'SV-75345' do
  title 'The Arista Multilayer Switch must support organizational requirements to conduct backups of system-level information contained in the information system when changes occur or weekly, whichever is sooner.'
  desc 'System-level information includes default and customized settings and security attributes, including ACLs that relate to the network device configuration, as well as software required for the execution and operation of the device. Information system backup is a critical step in ensuring system integrity and availability. If the system fails and there is no backup of the system-level information, a denial of service condition is possible for all who utilize this critical network component.

This control requires the network device to support the organizational central backup process for system-level information associated with the network device. This function may be provided by the network device itself; however, the preferred best practice is a centralized backup rather than each network device performing discrete backups.'
  desc 'check', 'Check the network device to determine if the network device is configured to conduct backups of system-level information contained in the information system when changes occur or weekly, whichever is sooner. 

If the network device does not support the organizational requirements to conduct backups of system-level data according to the defined frequency, this is a finding.'
  desc 'fix', "Configure the network device to conduct backups of system-level information contained in the information system when changes occur or weekly, whichever is sooner.

For weekly backups, the following chronologically scheduled command will back up the switch information one per day at noon:

switch(config)#schedule [name] at [hh:mm:ss] interval 1440 max-log-files 100 command bash FastCli -p 15 -c $'enable\\nshow tech-support > scp:[remote destination/filename]\\n'

The following event-handler will schedule backups any time the configuration is changed and written to memory:

event-handler Copy-Config
trigger on-startup-config
action bash sudo ip netns exec ns-DATA scp /mnt/flash/startup-config [user@IPaddress/filepath/filename]
delay 5"
  impact 0.3
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61835r1_chk'
  tag severity: 'low'
  tag gid: 'V-60887'
  tag rid: 'SV-75345r1_rule'
  tag stig_id: 'AMLS-NM-000440'
  tag gtitle: 'SRG-APP-000516-NDM-000340'
  tag fix_id: 'F-66599r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000537']
  tag nist: ['CM-6 b', 'CP-9 (b)']
end
