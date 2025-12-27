control 'SV-88663' do
  title 'The Cisco IOS XE router must produce audit log records containing sufficient information to establish what type of event occurred.'
  desc 'It is essential for security personnel to know what is being done, what was attempted, where it was done, when it was done, and by whom it was done in order to compile an accurate risk assessment. Associating event types with detected events in the application and audit logs provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured network device. Without this capability, it would be difficult to establish, correlate, and investigate the events leading up to an outage or attack.'
  desc 'check', 'Verify that logging is properly configured on the Cisco IOS XE router.

The configuration will look similar to the example below:

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If logging is not configured to produce audit log records containing sufficient information to establish what type of event occurred, this is a finding.'
  desc 'fix', 'Enter the following commands to enable auditing.

The configuration will look similar to the example below:

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74071r3_chk'
  tag severity: 'low'
  tag gid: 'V-73989'
  tag rid: 'SV-88663r2_rule'
  tag stig_id: 'CISR-ND-000027'
  tag gtitle: 'SRG-APP-000095-NDM-000225'
  tag fix_id: 'F-80529r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
