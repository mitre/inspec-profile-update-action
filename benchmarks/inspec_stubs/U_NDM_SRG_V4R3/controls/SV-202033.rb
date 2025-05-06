control 'SV-202033' do
  title 'The network device must produce audit log records containing information to establish the source of events.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event.  The source may be a component, module, or process within the device or an external session, administrator, or device.

Associating information about where the source of the event occurred provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.'
  desc 'check', 'Determine if the network device is configured to produce audit records containing information to establish the source (apparent cause) of the event. If the network device does not produce audit records containing information to establish the source of the event, this is a finding.'
  desc 'fix', 'Configure the network device to produce audit records containing information to establish the source of the event.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2159r381665_chk'
  tag severity: 'medium'
  tag gid: 'V-202033'
  tag rid: 'SV-202033r879566_rule'
  tag stig_id: 'SRG-APP-000098-NDM-000228'
  tag gtitle: 'SRG-APP-000098'
  tag fix_id: 'F-2160r381666_fix'
  tag 'documentable'
  tag legacy: ['SV-69375', 'V-55129']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
