control 'SV-220613' do
  title 'The Cisco switch must be configured to generate log records for privileged activities.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco switch configuration to verify that it generates log records for privileged activities as shown in the example configurations below:

archive
 log config
 logging enable

If the Cisco switch is not configured to generate log records for privileged activities, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to generate log records for privileged activities as shown in the example below:

SW4(config)#archive
SW4(config-archive)#log config
SW4(config-archive-log-cfg)#logging enable
SW4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22328r507885_chk'
  tag severity: 'medium'
  tag gid: 'V-220613'
  tag rid: 'SV-220613r879875_rule'
  tag stig_id: 'CISC-ND-001270'
  tag gtitle: 'SRG-APP-000504-NDM-000321'
  tag fix_id: 'F-22317r507886_fix'
  tag 'documentable'
  tag legacy: ['SV-110455', 'V-101351']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
