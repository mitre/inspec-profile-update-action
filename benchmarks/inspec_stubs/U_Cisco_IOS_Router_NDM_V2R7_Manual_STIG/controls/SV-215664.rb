control 'SV-215664' do
  title 'The Cisco router must be configured to automatically audit account modification.'
  desc 'Since the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. Auditing account modification along with an automatic notification to appropriate individuals will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', 'Review the router configuration to determine if it automatically audits account modification. The configuration should look similar to the example below:

archive
 log config
 logging enable

Note: Configuration changes can be viewed using the show archive log config all command.

If account modification is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the router to log account modification using the following commands:

R4(config)#archive
R4(config-archive)#log config
R4(config-archive-log-cfg)#logging enable
R4(config-archive-log-cfg)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16858r285954_chk'
  tag severity: 'medium'
  tag gid: 'V-215664'
  tag rid: 'SV-215664r879526_rule'
  tag stig_id: 'CISC-ND-000100'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-16856r285955_fix'
  tag 'documentable'
  tag legacy: ['V-96017', 'SV-105155']
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
