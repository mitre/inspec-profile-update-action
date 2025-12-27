control 'SV-80663' do
  title 'The HP FlexFabric Switch must initiate session auditing upon startup.'
  desc 'If auditing is enabled late in the startup process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', 'Enable info-center feature on the HP FlexFabric Switch:

[HP] info-center enable

Note:  By default, the information center is enabled.'
  impact 0.3
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66819r1_chk'
  tag severity: 'low'
  tag gid: 'V-66173'
  tag rid: 'SV-80663r1_rule'
  tag stig_id: 'HFFS-ND-000025'
  tag gtitle: 'SRG-APP-000092-NDM-000224'
  tag fix_id: 'F-72249r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
