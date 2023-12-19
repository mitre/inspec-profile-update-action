control 'SV-215704' do
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
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16898r286074_chk'
  tag severity: 'medium'
  tag gid: 'V-215704'
  tag rid: 'SV-215704r521266_rule'
  tag stig_id: 'CISC-ND-001260'
  tag gtitle: 'SRG-APP-000503-NDM-000320'
  tag fix_id: 'F-16896r286075_fix'
  tag 'documentable'
  tag legacy: ['SV-105293', 'V-96155']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
