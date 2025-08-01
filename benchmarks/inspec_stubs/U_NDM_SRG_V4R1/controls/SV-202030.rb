control 'SV-202030' do
  title 'The network device must produce audit log records containing sufficient information to establish what type of event occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. Without this capability, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.'
  desc 'check', 'Determine if the network device produces audit log records containing sufficient information to establish what type of event occurred. If the network device does not produce audit log records containing sufficient information to establish what type of event occurred, this is a finding.'
  desc 'fix', 'Configure the network device to produce audit log records containing sufficient information to establish what type of event occurred.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2156r381656_chk'
  tag severity: 'medium'
  tag gid: 'V-202030'
  tag rid: 'SV-202030r395721_rule'
  tag stig_id: 'SRG-APP-000095-NDM-000225'
  tag gtitle: 'SRG-APP-000095'
  tag fix_id: 'F-2157r381657_fix'
  tag 'documentable'
  tag legacy: ['SV-69341', 'V-55095']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
