control 'SV-220560' do
  title 'The Cisco switch must be configured to generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the examples below:

login on-failure log
login on-success log

If the Cisco switch is not configured to generate audit records when successful/unsuccessful logon attempts occur, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to generate audit records when successful/unsuccessful logon attempts occur as shown in the example below:

R5(config)#login on-failure log
R5(config)#login on-success log'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22275r508624_chk'
  tag severity: 'medium'
  tag gid: 'V-220560'
  tag rid: 'SV-220560r879874_rule'
  tag stig_id: 'CISC-ND-001260'
  tag gtitle: 'SRG-APP-000503-NDM-000320'
  tag fix_id: 'F-22264r508625_fix'
  tag 'documentable'
  tag legacy: ['SV-110575', 'V-101471']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
