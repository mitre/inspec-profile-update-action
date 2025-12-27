control 'SV-80671' do
  title 'The HP FlexFabric Switch must produce audit log records containing information to establish the source of events.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event. The source may be a component, module, or process within the device or an external session, administrator, or device.

Associating information about where the source of the event occurred provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.'
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', 'Enable info-center feature on the HP FlexFabric Switch:

[HP] info-center enable

Note:  By default, the information center is enabled.'
  impact 0.3
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66827r1_chk'
  tag severity: 'low'
  tag gid: 'V-66181'
  tag rid: 'SV-80671r1_rule'
  tag stig_id: 'HFFS-ND-000029'
  tag gtitle: 'SRG-APP-000098-NDM-000228'
  tag fix_id: 'F-72257r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
