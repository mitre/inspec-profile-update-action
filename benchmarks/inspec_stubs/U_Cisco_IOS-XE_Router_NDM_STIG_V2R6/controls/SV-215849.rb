control 'SV-215849' do
  title 'The Cisco router must be configured to generate audit records when successful/unsuccessful logon attempts occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the examples below.

login on-failure log
login on-success log

If the Cisco router is not configured to generate audit records when successful/unsuccessful logon attempts occur, this is a finding.'
  desc 'fix', 'Configure the Cisco router to generate audit records when successful/unsuccessful logon attempts occur as shown in the example below.

R5(config)#login on-failure log
R5(config)#login on-success log'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router NDM'
  tag check_id: 'C-17088r287586_chk'
  tag severity: 'medium'
  tag gid: 'V-215849'
  tag rid: 'SV-215849r879874_rule'
  tag stig_id: 'CISC-ND-001260'
  tag gtitle: 'SRG-APP-000503-NDM-000320'
  tag fix_id: 'F-17086r287587_fix'
  tag 'documentable'
  tag legacy: ['SV-105475', 'V-96337']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
