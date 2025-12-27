control 'SV-220571' do
  title 'The Cisco switch must be configured to automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. 

Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Review the switch configuration to determine if it automatically audits account creation. The configuration should look similar to the example below:

archive
 log config
 logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If account creation is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the switch to log account creation using the following commands:

SW4(config)#archive
SW4(config-archive)#log config
SW4(config-archive-log-cfg)#logging enable
SW4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22286r507759_chk'
  tag severity: 'medium'
  tag gid: 'V-220571'
  tag rid: 'SV-220571r521267_rule'
  tag stig_id: 'CISC-ND-000090'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-22275r507760_fix'
  tag 'documentable'
  tag legacy: ['SV-110371', 'V-101267']
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
