control 'SV-220572' do
  title 'The Cisco switch must be configured to automatically audit account modification.'
  desc 'Because the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. 

Auditing account modification, along with an automatic notification to appropriate individuals, will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', 'Review the switch configuration to determine if it automatically audits account modification. The configuration should look similar to the example below:

archive
 log config
 logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If account modification is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the switch to log account modification using the following commands:

SW4(config)#archive
SW4(config-archive)#log config
SW4(config-archive-log-cfg)#logging enable
SW4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch NDM'
  tag check_id: 'C-22287r507762_chk'
  tag severity: 'medium'
  tag gid: 'V-220572'
  tag rid: 'SV-220572r521267_rule'
  tag stig_id: 'CISC-ND-000100'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-22276r507763_fix'
  tag 'documentable'
  tag legacy: ['SV-110373', 'V-101269']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
