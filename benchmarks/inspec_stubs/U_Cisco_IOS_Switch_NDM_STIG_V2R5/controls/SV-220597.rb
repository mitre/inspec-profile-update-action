control 'SV-220597' do
  title 'The Cisco switch must be configured to automatically audit account enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to enable a new or disabled account. Notification of account enabling is one method for mitigating this risk.

 A comprehensive account management process will ensure an audit trail that documents the creation of application user accounts and notifies administrators and Information System Security Officers (ISSOs). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'Review the switch configuration to determine if it automatically audits account enabling. The configuration should look similar to the example below:

archive
 log config
 logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If account enabling is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the switch to log account enabling using the following commands:

SW4(config)#archive
SW4(config-archive)#log config
SW4(config-archive-log-cfg)#logging enable
SW4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22312r507837_chk'
  tag severity: 'medium'
  tag gid: 'V-220597'
  tag rid: 'SV-220597r879696_rule'
  tag stig_id: 'CISC-ND-000880'
  tag gtitle: 'SRG-APP-000319-NDM-000283'
  tag fix_id: 'F-22301r507838_fix'
  tag 'documentable'
  tag legacy: ['SV-110423', 'V-101319']
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
