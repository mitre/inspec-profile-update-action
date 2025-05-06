control 'SV-88639' do
  title 'The Cisco IOS XE router must automatically audit account creation.'
  desc 'Upon gaining access to a network device, an attacker will often first attempt to create a persistent method of reestablishing access. One way to accomplish this is to create a new account. Notification of account creation helps to mitigate this risk. Auditing account creation provides the necessary reconciliation that account management procedures are being followed. Without this audit trail, personnel without the proper authorization may gain access to critical network nodes.'
  desc 'check', 'Review the Cisco IOS XE router configuration to determine if it automatically audits account creation.

The configuration should look similar to the example below:

logging userinfo
archive
 log config
  logging enable
  logging size 1000
  notify syslog contenttype plaintext
  hidekeys

If account creation is not automatically audited, this is a finding.'
  desc 'fix', 'Configure the Cisco IOS XE router to automatically audit the creation of accounts.

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
  tag check_id: 'C-74047r3_chk'
  tag severity: 'medium'
  tag gid: 'V-73965'
  tag rid: 'SV-88639r2_rule'
  tag stig_id: 'CISR-ND-000009'
  tag gtitle: 'SRG-APP-000026-NDM-000208'
  tag fix_id: 'F-80505r3_fix'
  tag 'documentable'
  tag cci: ['CCI-000018']
  tag nist: ['AC-2 (4)']
end
