control 'SV-80959' do
  title 'The Juniper SRX Services Gateway must automatically generate a log event when accounts are enabled.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies administrators and Information System Security Officers (ISSO). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.

Accounts can be disabled by configuring the account with the build-in login class "unauthorized". When the command is reissued with a different login class, the account is enabled.'
  desc 'check', 'Verify the device is configured to display change-log events of severity info.

[edit]
show system syslog

If the system is not configured to generate a log record when account enabling actions occur, this is a finding.'
  desc 'fix', "The following commands configure the device to immediately display a message to any currently logged on administrator's console when changes are made to the configuration.

[edit]
set system syslog host <IP-syslog-server> any any
set system syslog file account-actions change-log any any"
  impact 0.5
  ref 'DPMS Target Juniper SRX SG NDM'
  tag check_id: 'C-67115r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66469'
  tag rid: 'SV-80959r1_rule'
  tag stig_id: 'JUSX-DM-000023'
  tag gtitle: 'SRG-APP-000319-NDM-000283'
  tag fix_id: 'F-72545r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
