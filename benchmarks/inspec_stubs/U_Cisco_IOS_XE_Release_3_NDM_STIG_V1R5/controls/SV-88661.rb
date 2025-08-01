control 'SV-88661' do
  title 'The Cisco IOS XE router must initiate session auditing upon startup.'
  desc 'If auditing is enabled late in the start-up process, the actions of some start-up processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.'
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

If logging is not configured, this is a finding.'
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
  tag check_id: 'C-74069r5_chk'
  tag severity: 'low'
  tag gid: 'V-73987'
  tag rid: 'SV-88661r2_rule'
  tag stig_id: 'CISR-ND-000026'
  tag gtitle: 'SRG-APP-000092-NDM-000224'
  tag fix_id: 'F-80527r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
