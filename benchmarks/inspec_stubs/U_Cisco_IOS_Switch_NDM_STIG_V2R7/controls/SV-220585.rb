control 'SV-220585' do
  title 'The Cisco switch must be configured to limit privileges to change the software resident within software libraries.'
  desc 'Changes to any software components of the network device can have significant effects on the overall security of the network. Therefore, only qualified and authorized individuals should be allowed administrative access to the network device for implementing any changes or upgrades. 

If the network device were to enable unauthorized users to make changes to software libraries, those changes could be implemented without undergoing testing, validation, and approval.'
  desc 'check', 'Review the Cisco switch configuration to verify that it limits software change privileges.

Step 1: If persistent logging is enabled as shown in the example below, go to Step 2. Otherwise, this requirement is not applicable.

logging persistent url disk0:/logfile size 134217728 filesize 16384

Step 2: Verify that the switch is not configured with a privilege level other than "15" to allow access to the file system as shown in the example below:

file privilege 10 

Note: The default privilege level required for access to the file system is "15"; hence, the command file privilege "15" will not be shown in the configuration.

If the switch is configured with a privilege level other than "15" to allow access to the file system, this is a finding.'
  desc 'fix', 'If persistent logging is enabled, configure the switch to only allow administrators with privilege level "15" access to the file system as shown in the example below:

SW4(config)#file privilege 15'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22300r507801_chk'
  tag severity: 'medium'
  tag gid: 'V-220585'
  tag rid: 'SV-220585r879586_rule'
  tag stig_id: 'CISC-ND-000460'
  tag gtitle: 'SRG-APP-000133-NDM-000244'
  tag fix_id: 'F-22289r507802_fix'
  tag 'documentable'
  tag legacy: ['SV-110399', 'V-101295']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
