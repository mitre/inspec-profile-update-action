control 'SV-88707' do
  title 'The Cisco IOS XE router must automatically audit account enabling actions.'
  desc 'Once an attacker establishes initial access to a system, the attacker often attempts to create a persistent method of reestablishing access. One way to accomplish this is for the attacker to simply enable a new or disabled account. Notification of account enabling is one method for mitigating this risk. A comprehensive account management process will ensure an audit trail which documents the creation of application user accounts and notifies administrators and Information System Security Officers (ISSO). Such a process greatly reduces the risk that accounts will be surreptitiously created and provides logging that can be used for forensic purposes.'
  desc 'check', 'Verify that the Cisco IOS XE router automatically audits account enabling actions.

The configuration should look similar to the example below:

logging userinfo

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If account enabling actions are not audited, this is a finding.'
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
  tag check_id: 'C-74123r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74033'
  tag rid: 'SV-88707r2_rule'
  tag stig_id: 'CISR-ND-000087'
  tag gtitle: 'SRG-APP-000319-NDM-000283'
  tag fix_id: 'F-80575r3_fix'
  tag 'documentable'
  tag cci: ['CCI-002130']
  tag nist: ['AC-2 (4)']
end
