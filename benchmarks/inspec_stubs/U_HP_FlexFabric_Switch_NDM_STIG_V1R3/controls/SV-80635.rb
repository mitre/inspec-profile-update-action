control 'SV-80635' do
  title 'The HP FlexFabric Switch must automatically audit account modification.'
  desc 'Since the accounts in the HP FlexFabric Switch are privileged or system-level accounts, account management is vital to the security of the HP FlexFabric Switch. Account management by a designated authority ensures access to the HP FlexFabric Switch is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. Auditing account modification along with an automatic notification to appropriate individuals will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', "Enable info-center feature on the HP FlexFabric Switch:

[HP] info-center enable

Note:  By default, the information center is enabled. Account modification on the SUT generates an automatic log entry in the system's log."
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66791r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66145'
  tag rid: 'SV-80635r1_rule'
  tag stig_id: 'HFFS-ND-000010'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-72221r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
