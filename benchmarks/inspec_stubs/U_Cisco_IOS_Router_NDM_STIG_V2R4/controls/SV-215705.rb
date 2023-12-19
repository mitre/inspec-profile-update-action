control 'SV-215705' do
  title 'The Cisco router must be configured to generate log records for privileged activities.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco router configuration to verify that it is compliant with this requirement as shown in the example configurations below.

archive
 log config
 logging enable

If the Cisco router is not configured to generate log records for privileged activities, this is a finding.'
  desc 'fix', 'Configure the Cisco router to generate log records for privileged activities as shown in the example below.

R4(config)#archive
R4(config-archive)#log config
R4(config-archive-log-cfg)#logging enable
R4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16899r286077_chk'
  tag severity: 'medium'
  tag gid: 'V-215705'
  tag rid: 'SV-215705r521266_rule'
  tag stig_id: 'CISC-ND-001270'
  tag gtitle: 'SRG-APP-000504-NDM-000321'
  tag fix_id: 'F-16897r286078_fix'
  tag 'documentable'
  tag legacy: ['SV-105295', 'V-96157']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
