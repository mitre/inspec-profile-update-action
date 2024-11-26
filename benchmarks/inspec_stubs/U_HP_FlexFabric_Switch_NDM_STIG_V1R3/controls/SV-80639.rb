control 'SV-80639' do
  title 'The HP FlexFabric Switch must automatically audit account removal actions.'
  desc 'Account management, as a whole, ensures access to the HP FlexFabric Switch is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', "Enable info-center feature on the HP FlexFabric Switch:

[HP] info-center enable

Note:  By default, the information center is enabled. Account removal actions on the SUT generates an automatic log entry in the system's log."
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66795r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66149'
  tag rid: 'SV-80639r1_rule'
  tag stig_id: 'HFFS-ND-000012'
  tag gtitle: 'SRG-APP-000029-NDM-000211'
  tag fix_id: 'F-72225r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
