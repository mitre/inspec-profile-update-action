control 'SV-220611' do
  title 'The Cisco switch must be configured to generate log records when administrator privileges are deleted.'
  desc 'Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

Audit records can be generated from various components within the network device (e.g., module or policy filter).'
  desc 'check', 'Review the Cisco switch configuration to verify that it generates log records when administrator privileges are deleted as shown in the example below:

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
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22326r507879_chk'
  tag severity: 'medium'
  tag gid: 'V-220611'
  tag rid: 'SV-220611r521267_rule'
  tag stig_id: 'CISC-ND-001250'
  tag gtitle: 'SRG-APP-000499-NDM-000319'
  tag fix_id: 'F-22315r507880_fix'
  tag 'documentable'
  tag legacy: ['SV-110451', 'V-101347']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
