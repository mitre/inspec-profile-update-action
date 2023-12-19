control 'SV-220559' do
  title 'The Cisco switch must be configured to generate log records when administrator privileges are deleted.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco switch configuration to verify that it is compliant with this requirement as shown in the example below:

archive
 log config
 logging enable

If the Cisco switch is not configured to generate log records when administrator privileges are deleted, this is a finding.'
  desc 'fix', 'Configure the Cisco switch to generate log records when administrator privileges are deleted as shown in the example below:

SW4(config)#archive
SW4(config-archive)#log config
SW4(config-archive-log-cfg)#logging enable
SW4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22274r508621_chk'
  tag severity: 'medium'
  tag gid: 'V-220559'
  tag rid: 'SV-220559r531084_rule'
  tag stig_id: 'CISC-ND-001250'
  tag gtitle: 'SRG-APP-000499-NDM-000319'
  tag fix_id: 'F-22263r508622_fix'
  tag 'documentable'
  tag legacy: ['SV-110573', 'V-101469']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
