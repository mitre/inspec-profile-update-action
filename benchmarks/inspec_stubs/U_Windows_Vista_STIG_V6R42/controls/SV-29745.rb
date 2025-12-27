control 'SV-29745' do
  title 'The system does not have a backup administrator account'
  desc 'The built-in administrator account, as a well known account subject to attack, is disabled by default and per STIG requirements.  Domain Admins on domain joined systems should provide sufficient availability for administering a system.  A site with limited administrators must ensure they have a contingency for administering a non-domain system.'
  desc 'check', 'Determine if there is a contingency for administering a non-domain system with limited administrators.  If a backup administrator account exists it must be documented with the IAO and it must be stored with its password in a secure location.'
  desc 'fix', 'Create a contingency plan for administering a system in emergency situations.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-41761r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14224'
  tag rid: 'SV-29745r2_rule'
  tag gtitle: 'Backup Administrator Account'
  tag fix_id: 'F-37540r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
