control 'SV-202032' do
  title 'The network device must produce audit records containing information to establish where the events occurred.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as device hardware components, device software modules, session identifiers, filenames, host names, and functionality.

Associating information about where the event occurred within the network device provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.'
  desc 'check', 'Determine if the network device is configured to produce audit records containing information to establish where the events occurred. If the network device does not produce audit records containing information to establish where the events occurred, this is a finding.'
  desc 'fix', 'Configure the network device to produce audit records containing information to establish where the events occurred.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2158r381662_chk'
  tag severity: 'medium'
  tag gid: 'V-202032'
  tag rid: 'SV-202032r879565_rule'
  tag stig_id: 'SRG-APP-000097-NDM-000227'
  tag gtitle: 'SRG-APP-000097'
  tag fix_id: 'F-2159r381663_fix'
  tag 'documentable'
  tag legacy: ['SV-69345', 'V-55099']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
