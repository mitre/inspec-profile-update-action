control 'SV-215847' do
  title 'The Cisco router must be configured to generate log records when administrator privileges are modified.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the examples below.

hostname R4
!
!
logging userinfo
…
…
…
archive
 log config
 logging enable

Note: The logging userinfo command will log when the administrator increases his or her privilege level while the log config command will log all configuration changes such as changing privilege levels for certain commands.

If the Cisco router is not configured to generate log records when administrator privileges are modified, this is a finding.'
  desc 'fix', 'Configure the Cisco router to generate log records when account privileges are modified as shown in the example below.

R4(config)#logging userinfo 
R4(config)#archive
R4(config-archive)#log config
R4(config-archive-log-cfg)#logging enable
R4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17086r287580_chk'
  tag severity: 'medium'
  tag gid: 'V-215847'
  tag rid: 'SV-215847r531083_rule'
  tag stig_id: 'CISC-ND-001240'
  tag gtitle: 'SRG-APP-000495-NDM-000318'
  tag fix_id: 'F-17084r287581_fix'
  tag 'documentable'
  tag legacy: ['SV-105471', 'V-96333']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
