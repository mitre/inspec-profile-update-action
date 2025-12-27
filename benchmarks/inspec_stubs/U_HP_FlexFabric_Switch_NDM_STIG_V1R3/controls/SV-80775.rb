control 'SV-80775' do
  title 'The HP FlexFabric Switch must generate audit log events for a locally developed list of auditable events.'
  desc 'Auditing and logging are key components of any security architecture. Logging the actions of specific events provides a means to investigate an attack; to recognize resource utilization or capacity thresholds; or to identify an improperly configured network device. If auditing is not comprehensive, it will not be useful for intrusion monitoring, security investigations, and forensic analysis.'
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', 'Enable info-center feature on the HP FlexFabric Switch: 

[HP] info-center enable

Note:  By default, the information center is enabled.'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66931r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66285'
  tag rid: 'SV-80775r1_rule'
  tag stig_id: 'HFFS-ND-000131'
  tag gtitle: 'SRG-APP-000516-NDM-000334'
  tag fix_id: 'F-72361r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
