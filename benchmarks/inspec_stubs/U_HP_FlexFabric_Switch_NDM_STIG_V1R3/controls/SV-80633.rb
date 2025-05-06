control 'SV-80633' do
  title 'The HP FlexFabric Switch must automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', "Enable info-center feature on the HP FlexFabric Switch:

[HP] info-center enable

Note:  By default, the information center is enabled. Account creation on the SUT generates an automatic log entry in the system's log."
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66789r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66143'
  tag rid: 'SV-80633r1_rule'
  tag stig_id: 'HFFS-ND-000009'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-72219r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
