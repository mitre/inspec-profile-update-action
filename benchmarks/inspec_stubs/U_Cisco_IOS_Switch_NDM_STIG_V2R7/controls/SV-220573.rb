control 'SV-220573' do
  title 'The Cisco switch must be configured to automatically audit account disabling actions.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account disabling actions will support account management procedures. 

When device management accounts are disabled, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Review the switch configuration to determine if it automatically audits account disabling. The configuration should look similar to the example below:

archive
 log config
 logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If account disabling is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the switch to log account disabling using the following commands:

SW4(config)#archive
SW4(config-archive)#log config
SW4(config-archive-log-cfg)#logging enable
SW4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22288r507765_chk'
  tag severity: 'medium'
  tag gid: 'V-220573'
  tag rid: 'SV-220573r879527_rule'
  tag stig_id: 'CISC-ND-000110'
  tag gtitle: 'SRG-APP-000028-NDM-000210'
  tag fix_id: 'F-22277r507766_fix'
  tag 'documentable'
  tag legacy: ['SV-110375', 'V-101271']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
