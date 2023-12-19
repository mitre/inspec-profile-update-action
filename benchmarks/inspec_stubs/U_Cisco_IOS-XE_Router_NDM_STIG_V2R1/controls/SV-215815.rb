control 'SV-215815' do
  title 'The Cisco router must be configured to protect against an individual falsely denying having performed organization-defined actions to be covered by non-repudiation.'
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
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17054r287484_chk'
  tag severity: 'medium'
  tag gid: 'V-215815'
  tag rid: 'SV-215815r531083_rule'
  tag stig_id: 'CISC-ND-000210'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-17052r287485_fix'
  tag 'documentable'
  tag legacy: ['V-96217', 'SV-105355']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
