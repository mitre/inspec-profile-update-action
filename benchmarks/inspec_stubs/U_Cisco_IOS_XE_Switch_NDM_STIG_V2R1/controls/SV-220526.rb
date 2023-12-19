control 'SV-220526' do
  title 'The Cisco switch must be configured to protect against an individual falsely denying having performed organization-defined actions to be covered by non-repudiation.'
  desc 'This requirement supports non-repudiation of actions taken by an administrator and is required in order to maintain the integrity of the configuration management process. All configuration changes to the network device are logged, and administrators authenticate with two-factor authentication before gaining administrative access. Together, these processes will ensure the administrators can be held accountable for the configuration changes they implement.

To meet this requirement, the network device must log administrator access and activity.'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the example below:

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
  desc 'fix', 'Configure the switch to log administrator activity as shown in the example below:

SW1(config)#logging userinfo
SW1(config)#archive
SW1(config-archive)#log config
SW1(config-archive-log-cfg)#logging enable
SW1(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22241r508522_chk'
  tag severity: 'medium'
  tag gid: 'V-220526'
  tag rid: 'SV-220526r531084_rule'
  tag stig_id: 'CISC-ND-000210'
  tag gtitle: 'SRG-APP-000080-NDM-000220'
  tag fix_id: 'F-22230r508523_fix'
  tag 'documentable'
  tag legacy: ['V-101403', 'SV-110507']
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
