control 'SV-220579' do
  title 'The Cisco switch must be configured to generate audit records when successful/unsuccessful attempts to log on with access privileges occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

Audit records can be generated from various components within the information system (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco switch configuration to verify that it generates audit records of all logon attempts. The configuration example below will log all logon attempts:

login on-failure log
login on-success log

If the Cisco switch is not configured to generate audit records of successful/unsuccessful attempts to log on, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to log all logon attempts as shown in the example below:

SW1(config)#login on-failure log
SW1(config)#login on-success log
SW1(config)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22294r507783_chk'
  tag severity: 'medium'
  tag gid: 'V-220579'
  tag rid: 'SV-220579r521267_rule'
  tag stig_id: 'CISC-ND-000250'
  tag gtitle: 'SRG-APP-000091-NDM-000223'
  tag fix_id: 'F-22283r507784_fix'
  tag 'documentable'
  tag legacy: ['SV-110387', 'V-101283']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
