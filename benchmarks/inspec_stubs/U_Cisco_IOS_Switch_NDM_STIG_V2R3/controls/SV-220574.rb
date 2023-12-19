control 'SV-220574' do
  title 'The Cisco switch must be configured to automatically audit account removal actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. 

When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Review the switch configuration to determine if it automatically audits account removal. The configuration should look similar to the example below:

archive
 log config
 logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If account removal is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the switch to log account removal using the following commands:

SW4(config)#archive
SW4(config-archive)#log config
SW4(config-archive-log-cfg)#logging enable
SW4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22289r507768_chk'
  tag severity: 'medium'
  tag gid: 'V-220574'
  tag rid: 'SV-220574r521267_rule'
  tag stig_id: 'CISC-ND-000120'
  tag gtitle: 'SRG-APP-000029-NDM-000211'
  tag fix_id: 'F-22278r507769_fix'
  tag 'documentable'
  tag legacy: ['SV-110377', 'V-101273']
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
