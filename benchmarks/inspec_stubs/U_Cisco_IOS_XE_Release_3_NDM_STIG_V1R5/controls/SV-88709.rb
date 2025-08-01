control 'SV-88709' do
  title 'The Cisco IOS XE router must audit the execution of privileged functions.'
  desc 'Misuse of privileged functions, either intentionally or unintentionally by authorized users, or by unauthorized external entities that have compromised information system accounts, is a serious and ongoing concern and can have significant adverse impacts on organizations. Auditing the use of privileged functions is one way to detect such misuse and identify the risk from insider threats and the advanced persistent threat.'
  desc 'check', 'Verify that the Cisco IOS XE router automatically audits execution of privileged functions.

The configuration should look similar to the example below:

logging userinfo

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If privileged functions are not audited, this is a finding.'
  desc 'fix', 'Enter the following commands to enable auditing:
 
logging userinfo

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74125r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74035'
  tag rid: 'SV-88709r2_rule'
  tag stig_id: 'CISR-ND-000093'
  tag gtitle: 'SRG-APP-000343-NDM-000289'
  tag fix_id: 'F-80577r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002234']
  tag nist: ['AC-6 (9)']
end
