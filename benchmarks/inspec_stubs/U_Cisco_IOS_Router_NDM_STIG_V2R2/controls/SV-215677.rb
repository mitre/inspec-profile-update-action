control 'SV-215677' do
  title 'The Cisco router must be configured to limit privileges to change the software resident within software libraries.'
  desc 'Changes to any software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. If the network device were to enable non-authorized users to make changes to software libraries, those changes could be implemented without undergoing testing, validation, and approval.'
  desc 'check', 'Verify that the router is not configured with a privilege level other than "15" to allow access to the file system as shown in the example below.

file privilege 10 

Note: The default privilege level required for access to the file system is "15"; hence, the command file privilege "15" will not be shown in the configuration.

If the router is configured with a privilege level other than "15" to allow access to the file system, this is a finding.'
  desc 'fix', 'Configure the router to only allow administrators with privilege level "15" access to the file system as shown in the example below.

R4(config)#file privilege 15'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16871r285993_chk'
  tag severity: 'medium'
  tag gid: 'V-215677'
  tag rid: 'SV-215677r521266_rule'
  tag stig_id: 'CISC-ND-000460'
  tag gtitle: 'SRG-APP-000133-NDM-000244'
  tag fix_id: 'F-16869r285994_fix'
  tag 'documentable'
  tag legacy: ['SV-105193', 'V-96055']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
