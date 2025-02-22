control 'SV-88667' do
  title 'The Cisco IOS XE router must produce audit records containing information to establish where the events occurred.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know where events occurred, such as device hardware components, device software modules, session identifiers, filenames, host names, and functionality.

Associating information about where the event occurred within the network device provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.'
  desc 'check', 'Verify that logging is properly configured on the Cisco IOS XE router.

The configuration will look similar to the example below:

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If logging is not configured to produce audit records containing information to establish where the events occurred, this is a finding.'
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
  tag check_id: 'C-74075r3_chk'
  tag severity: 'low'
  tag gid: 'V-73993'
  tag rid: 'SV-88667r2_rule'
  tag stig_id: 'CISR-ND-000029'
  tag gtitle: 'SRG-APP-000097-NDM-000227'
  tag fix_id: 'F-80533r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
