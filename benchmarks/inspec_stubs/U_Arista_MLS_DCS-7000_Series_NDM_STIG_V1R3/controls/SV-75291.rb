control 'SV-75291' do
  title 'The Arista Multilayer Switch must automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Review the switch configuration and verify that logging is enabled.

If logging is not enabled or is not enabled with sufficient detail to fulfill the specifications set forth in the VulDiscussion, this is a finding.

To determine if logging is enabled, enter: 

switch#show logging

The output must show logging as enabled, with a logging level of informational or debugging.

In order to ensure all user commands are captured, the following statement must be in the running config:

aaa accounting commands all default start-stop logging [group radius]'
  desc 'fix', 'Enable logging on the switch with sufficient detail to fulfill the specifications set forth in the VulDiscussion.

To configure logging to a remote syslog server at the informational level, enter:

switch#config
switch(config)#logging host [ip address]
switch(config)#logging trap informational

Then configure the following AAA:

aaa accounting commands all default start-stop logging [group radius]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-61781r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60835'
  tag rid: 'SV-75291r1_rule'
  tag stig_id: 'AMLS-NM-000120'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-66545r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
