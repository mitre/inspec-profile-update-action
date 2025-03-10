control 'SV-80637' do
  title 'The HP FlexFabric Switch must automatically audit account disabling actions.'
  desc 'Account management, as a whole, ensures access to the HP FlexFabric Switch is being controlled in a secure manner by granting access to only authorized personnel. Auditing account disabling actions will support account management procedures. When device management accounts are disabled, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', "Enable info-center feature on the HP FlexFabric Switch:

[HP] info-center enable

Note:  By default, the information center is enabled. Account disabling actions on the SUT generates an automatic log entry in the system's log."
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66793r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66147'
  tag rid: 'SV-80637r1_rule'
  tag stig_id: 'HFFS-ND-000011'
  tag gtitle: 'SRG-APP-000028-NDM-000210'
  tag fix_id: 'F-72223r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
