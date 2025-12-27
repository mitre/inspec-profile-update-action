control 'SV-202031' do
  title 'The network device must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Logging the date and time of each detected event provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. In order to establish and correlate the series of events leading up to an outage or attack, it is imperative the date and time are recorded in all log records.'
  desc 'check', 'Determine if the network device is configured to produce audit records containing information to establish when (date and time) the events occurred. If the network device does not produce audit records containing information to establish when the events occurred, this is a finding.'
  desc 'fix', 'Configure the network device to produce audit records containing information to establish when (date and time) the events occurred.'
  impact 0.5
  ref 'DPMS Target Network Device Management'
  tag check_id: 'C-2157r381659_chk'
  tag severity: 'medium'
  tag gid: 'V-202031'
  tag rid: 'SV-202031r879564_rule'
  tag stig_id: 'SRG-APP-000096-NDM-000226'
  tag gtitle: 'SRG-APP-000096'
  tag fix_id: 'F-2158r381660_fix'
  tag 'documentable'
  tag legacy: ['SV-69343', 'V-55097']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
