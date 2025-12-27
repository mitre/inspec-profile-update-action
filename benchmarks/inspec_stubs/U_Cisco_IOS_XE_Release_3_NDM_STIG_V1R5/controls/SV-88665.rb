control 'SV-88665' do
  title 'The Cisco IOS XE router must produce audit records containing information to establish when (date and time) the events occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Logging the date and time of each detected event provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. In order to establish and correlate the series of events leading up to an outage or attack, it is imperative the date and time are recorded in all log records.'
  desc 'check', 'Verify that logging is properly configured on the Cisco IOS XE router.

The configuration will look similar to the example below:

service timestamps log datetime

If time stamps is not configured, this is a finding.'
  desc 'fix', 'Enter the following commands to enable time stamps for auditing:

service timestamps log datetime'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74073r4_chk'
  tag severity: 'low'
  tag gid: 'V-73991'
  tag rid: 'SV-88665r2_rule'
  tag stig_id: 'CISR-ND-000028'
  tag gtitle: 'SRG-APP-000096-NDM-000226'
  tag fix_id: 'F-80531r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
