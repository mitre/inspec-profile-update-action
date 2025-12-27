control 'SV-80667' do
  title 'The HP FlexFabric Switch must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Logging the date and time of each detected event provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. In order to establish and correlate the series of events leading up to an outage or attack, it is imperative the date and time are recorded in all log records.'
  desc 'check', 'Determine if the info-center feature is enabled on the HP FlexFabric Switch:

[HP] display info-center

Information Center: Enabled

If logging is not enabled, this is a finding.'
  desc 'fix', 'Enable info-center feature on the HP FlexFabric Switch:

[HP] info-center enable

Note:  By default, the information center is enabled.'
  impact 0.3
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66823r1_chk'
  tag severity: 'low'
  tag gid: 'V-66177'
  tag rid: 'SV-80667r1_rule'
  tag stig_id: 'HFFS-ND-000027'
  tag gtitle: 'SRG-APP-000096-NDM-000226'
  tag fix_id: 'F-72253r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
