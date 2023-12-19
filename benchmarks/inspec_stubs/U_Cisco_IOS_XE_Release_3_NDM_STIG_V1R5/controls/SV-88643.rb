control 'SV-88643' do
  title 'The Cisco IOS XE router must automatically audit account removal.'
  desc 'Account management, as a whole, ensures access to the network device is being controlled in a secure manner by granting access to only authorized personnel. Auditing account removal actions will support account management procedures. When device management accounts are terminated, user or service accessibility may be affected. Auditing also ensures authorized active accounts remain enabled and available for use when required.'
  desc 'check', 'Review the Cisco IOS XE router configuration to determine if it automatically audits account removal.

The configuration should look similar to the example below:

logging userinfo
archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If account removal is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to automatically audit the removal of accounts.

The configuration should look similar to the example below:

logging userinfo
archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74051r3_chk'
  tag severity: 'medium'
  tag gid: 'V-73969'
  tag rid: 'SV-88643r2_rule'
  tag stig_id: 'CISR-ND-000012'
  tag gtitle: 'SRG-APP-000029-NDM-000211'
  tag fix_id: 'F-80509r3_fix'
  tag 'documentable'
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
