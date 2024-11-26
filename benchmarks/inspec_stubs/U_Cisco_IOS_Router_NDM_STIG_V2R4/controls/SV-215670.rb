control 'SV-215670' do
  title 'The Cisco device must be configured to audit all administrator activity.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

To meet this requirement, the network device must log administrator access and activity.'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example below.

hostname R1
!
logging userinfo
!
…
…
…
archive
 log config
 logging enable
!

Note: The logging userinfo global configuration command will generate a log when a user increases his or her privilege level.

If logging of administrator activity is not configured, this is a finding.'
  desc 'fix', 'Configure the router to log administrator activity as shown in the example below.

R1(config)#logging userinfo
R1(config)#archive
R1(config-archive)#log config
R1(config-archive-log-cfg)#logging enable
R1(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16864r285972_chk'
  tag severity: 'medium'
  tag gid: 'V-215670'
  tag rid: 'SV-215670r835036_rule'
  tag stig_id: 'CISC-ND-000210'
  tag gtitle: 'SRG-APP-000080-NDM-000345'
  tag fix_id: 'F-16862r285973_fix'
  tag 'documentable'
  tag legacy: ['SV-105173', 'V-96035']
  tag cci: ['CCI-000166', 'CCI-002234', 'CCI-000172']
  tag nist: ['AU-10', 'AC-6 (9)', 'AU-12 c']
end
