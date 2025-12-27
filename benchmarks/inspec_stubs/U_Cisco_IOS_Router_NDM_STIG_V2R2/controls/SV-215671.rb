control 'SV-215671' do
  title 'The Cisco router must be configured to generate audit records when successful/unsuccessful attempts to log on with access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement. The configuration example below will log all logon attempts.

login on-failure log
login on-success log

If the Cisco router is not configured to generate audit records when successful/unsuccessful attempts to logon, this is a finding.'
  desc 'fix', 'Configure the Cisco router to log all logon attempts as shown in the example below.

R1(config)#login on-failure log
R1(config)#login on-success log
R1(config)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16865r285975_chk'
  tag severity: 'medium'
  tag gid: 'V-215671'
  tag rid: 'SV-215671r521266_rule'
  tag stig_id: 'CISC-ND-000250'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-16863r285976_fix'
  tag 'documentable'
  tag legacy: ['SV-105177', 'V-96039']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
