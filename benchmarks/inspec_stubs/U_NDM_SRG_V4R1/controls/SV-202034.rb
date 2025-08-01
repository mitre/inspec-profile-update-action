control 'SV-202034' do
  title 'The network device must produce audit records that contain information to establish the outcome of the event.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the device after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Determine if the network device is configured to produce audit records that contain information to establish the outcome of the event. If the network device does not produce audit records that contain information to establish the outcome of the event, this is a finding.'
  desc 'fix', 'Configure the network device to produce audit records that contain information to establish the outcome of the event.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2160r381668_chk'
  tag severity: 'medium'
  tag gid: 'V-202034'
  tag rid: 'SV-202034r395733_rule'
  tag stig_id: 'SRG-APP-000099-NDM-000229'
  tag gtitle: 'SRG-APP-000099'
  tag fix_id: 'F-2161r381669_fix'
  tag 'documentable'
  tag legacy: ['SV-69383', 'V-55137']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
