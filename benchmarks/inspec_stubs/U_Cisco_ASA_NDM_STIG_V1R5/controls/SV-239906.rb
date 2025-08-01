control 'SV-239906' do
  title 'The Cisco ASA must be configured to produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Logging the date and time of each detected event provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. In order to establish and correlate the series of events leading up to an outage or attack, it is imperative the date and time are recorded in all log records.'
  desc 'check', 'Verify that the ASA is configured to include the date and time on all log records as shown in the configuration example below.

logging timestamp

If time stamp is not configured, this is a finding.'
  desc 'fix', 'Configure the ASA to include the date and time on all log records as shown in the example below.

ASA(config)# logging timestamp'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43139r666079_chk'
  tag severity: 'medium'
  tag gid: 'V-239906'
  tag rid: 'SV-239906r879564_rule'
  tag stig_id: 'CASA-ND-000270'
  tag gtitle: 'SRG-APP-000096-NDM-000226'
  tag fix_id: 'F-43098r666080_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
