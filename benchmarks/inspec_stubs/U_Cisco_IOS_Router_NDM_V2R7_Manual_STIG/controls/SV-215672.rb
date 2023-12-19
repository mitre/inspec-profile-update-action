control 'SV-215672' do
  title 'The Cisco router must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Logging the date and time of each detected event provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. In order to establish and correlate the series of events leading up to an outage or attack, it is imperative the date and time are recorded in all log records.'
  desc 'check', 'Verify that the router is configured to include the date and time on all log records as shown in the configuration example below.

service timestamps log datetime localtime

If time stamps is not configured, this is a finding.'
  desc 'fix', 'Configure the router to include the date and time on all log records as shown in the example below.

R1(config)#service timestamps log datetime localtime'
  impact 0.5
  ref 'DPMS Target Cisco IOS Router NDM'
  tag check_id: 'C-16866r285978_chk'
  tag severity: 'medium'
  tag gid: 'V-215672'
  tag rid: 'SV-215672r879564_rule'
  tag stig_id: 'CISC-ND-000280'
  tag gtitle: 'SRG-APP-000096-NDM-000226'
  tag fix_id: 'F-16864r285979_fix'
  tag 'documentable'
  tag legacy: ['V-96041', 'SV-105179']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
