control 'SV-80669' do
  title 'The HP FlexFabric Switch must produce audit records containing information to establish where the events occurred.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as device hardware components, device software modules, session identifiers, filenames, host names, and functionality.

Associating information about where the event occurred within the HP FlexFabric Switch provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.'
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', 'Enable info-center feature on the HP FlexFabric Switch:

[HP] info-center enable

Note:  By default, the information center is enabled.'
  impact 0.3
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66825r1_chk'
  tag severity: 'low'
  tag gid: 'V-66179'
  tag rid: 'SV-80669r1_rule'
  tag stig_id: 'HFFS-ND-000028'
  tag gtitle: 'SRG-APP-000097-NDM-000227'
  tag fix_id: 'F-72255r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
