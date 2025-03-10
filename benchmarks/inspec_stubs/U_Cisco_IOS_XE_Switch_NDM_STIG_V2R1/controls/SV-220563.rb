control 'SV-220563' do
  title 'The Cisco switch must be configured to generate log records when concurrent logons from different workstations occur.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the examples below:

login on-success log

If the Cisco switch is not configured to generate log records when concurrent logons from different workstations occur, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to generate log records when concurrent logons from different workstations occur as shown in the example below:

R5(config)#login on-success log'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22278r508633_chk'
  tag severity: 'medium'
  tag gid: 'V-220563'
  tag rid: 'SV-220563r531084_rule'
  tag stig_id: 'CISC-ND-001290'
  tag gtitle: 'SRG-APP-000506-NDM-000323'
  tag fix_id: 'F-22267r508634_fix'
  tag 'documentable'
  tag legacy: ['SV-110581', 'V-101477']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
