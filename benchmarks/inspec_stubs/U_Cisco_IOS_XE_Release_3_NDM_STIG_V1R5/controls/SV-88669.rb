control 'SV-88669' do
  title 'The Cisco IOS XE router must produce audit log records containing information to establish the source of events.'
  desc 'In order to compile an accurate risk assessment and provide forensic analysis, it is essential for security personnel to know the source of the event.  The source may be a component, module, or process within the device or an external session, administrator, or device.

Associating information about where the source of the event occurred provides a means of investigating an attack; recognizing resource utilization or capacity thresholds; or identifying an improperly configured device.'
  desc 'check', 'Verify that logging is properly configured on the Cisco IOS XE router.

The configuration will look similar to the example below:

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If logging is not configured to produce log records containing information to establish the source of events, this is a finding.'
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
  tag check_id: 'C-74077r3_chk'
  tag severity: 'low'
  tag gid: 'V-73995'
  tag rid: 'SV-88669r2_rule'
  tag stig_id: 'CISR-ND-000030'
  tag gtitle: 'SRG-APP-000098-NDM-000228'
  tag fix_id: 'F-80535r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
