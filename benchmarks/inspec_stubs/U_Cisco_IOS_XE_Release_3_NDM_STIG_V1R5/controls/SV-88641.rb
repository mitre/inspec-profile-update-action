control 'SV-88641' do
  title 'The Cisco IOS XE router must automatically audit account modification.'
  desc 'Since the accounts in the network device are privileged or system-level accounts, account management is vital to the security of the network device. Account management by a designated authority ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel with the appropriate and necessary privileges. Auditing account modification along with an automatic notification to appropriate individuals will provide the necessary reconciliation that account management procedures are being followed. If modifications to management accounts are not audited, reconciliation of account management procedures cannot be tracked.'
  desc 'check', 'Verify that the Cisco IOS XE router is configured to audit account modification.

The configuration should like similar to the example below:

logging userinfo

login on-failure log
login on-success log

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If account modification is not audited, this is a finding.'
  desc 'fix', 'Enter the following commands to audit account modification:  

logging userinfo

login on-failure log
login on-success log

archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74049r4_chk'
  tag severity: 'medium'
  tag gid: 'V-73967'
  tag rid: 'SV-88641r2_rule'
  tag stig_id: 'CISR-ND-000010'
  tag gtitle: 'SRG-APP-000027-NDM-000209'
  tag fix_id: 'F-80507r4_fix'
  tag 'documentable'
  tag cci: ['CCI-001403']
  tag nist: ['AC-2 (4)']
end
