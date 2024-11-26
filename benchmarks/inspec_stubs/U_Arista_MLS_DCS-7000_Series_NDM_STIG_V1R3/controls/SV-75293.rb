control 'SV-75293' do
  title 'The Arista Multilayer Switch must automatically audit account modification.'
  desc 'Since the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. Auditing account modification along with an automatic notification to appropriate individuals will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', 'Review the switch configuration and verify that logging is enabled.

If logging is not enabled or is not enabled with sufficient detail to fulfill the specifications set forth in the VulDiscussion, this is a finding.

To determine if logging is enabled, enter: 

switch#show logging

The output must show logging as enabled, with a logging level of informational or debugging.

In order to ensure all user commands are captured, the following statement must be in the running config.

aaa accounting commands all default start-stop logging [group radius]'
  desc 'fix', 'Enable logging on the switch with sufficient detail to fulfill the specifications set forth in the VulDiscussion.

To configure logging to a remote syslog server at the informational level, enter:

switch#config
switch(config)#logging host [ip address]
switch(config)#logging trap informational

Then configure the following AAA

aaa accounting commands all default start-stop logging [group radius]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61783r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60837'
  tag rid: 'SV-75293r1_rule'
  tag stig_id: 'AMLS-NM-000130'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-66547r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
