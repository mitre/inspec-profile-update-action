control 'SV-80673' do
  title 'The HP FlexFabric Switch must produce audit records that contain information to establish the outcome of the event.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the device after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', 'Enable info-center feature on the HP FlexFabric Switch:

[HP] info-center enable

Note:  By default, the information center is enabled.'
  impact 0.3
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66829r1_chk'
  tag severity: 'low'
  tag gid: 'V-66183'
  tag rid: 'SV-80673r1_rule'
  tag stig_id: 'HFFS-ND-000030'
  tag gtitle: 'SRG-APP-000099-NDM-000229'
  tag fix_id: 'F-72259r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
