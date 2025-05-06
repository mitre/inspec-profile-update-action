control 'SV-88671' do
  title 'The Cisco IOS XE router must produce audit records that contain information to establish the outcome of the event.'
  desc 'Without information about the outcome of events, security personnel cannot make an accurate assessment as to whether an attack was successful or if changes were made to the security state of the system.

Event outcomes can include indicators of event success or failure and event-specific results (e.g., the security state of the device after the event occurred). As such, they also provide a means to measure the impact of an event and help authorized personnel to determine the appropriate response.'
  desc 'check', 'Verify that logging is properly configured on the Cisco IOS XE router.

The configuration will look similar to the example below:

logging userinfo

login on-failure log
login on-success log

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If logging is not configured to log the outcome of events, this is a finding.'
  desc 'fix', 'Enter the following commands to enable auditing.

The configuration will look similar to the example below:

logging userinfo

login on-failure log
login on-success log

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74079r3_chk'
  tag severity: 'low'
  tag gid: 'V-73997'
  tag rid: 'SV-88671r2_rule'
  tag stig_id: 'CISR-ND-000031'
  tag gtitle: 'SRG-APP-000099-NDM-000229'
  tag fix_id: 'F-80537r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
