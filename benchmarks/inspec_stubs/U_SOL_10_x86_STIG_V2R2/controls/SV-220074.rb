control 'SV-220074' do
  title 'The system must disable accounts after three consecutive unsuccessful login attempts.'
  desc 'Disabling accounts after a limited number of unsuccessful login attempts improves protection against password guessing attacks.'
  desc 'check', 'Verify RETRIES is set in the login file.

# grep RETRIES /etc/default/login 
If RETRIES is not set or is more than 3, this is a finding.

Verify the account locks after invalid login attempts.
# grep LOCK_AFTER_RETRIES /etc/security/policy.conf  
If LOCK_AFTER_RETRIES is not set to YES,  this is a finding.'
  desc 'fix', 'Set RETRIES to 3 in the /etc/default/login file.
#vi /etc/default/login

Set LOCK_AFTER_RETRIES to YES in the /etc/security/policy.conf file.
#vi /etc/security/policy.conf'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-21783r488276_chk'
  tag severity: 'medium'
  tag gid: 'V-220074'
  tag rid: 'SV-220074r603266_rule'
  tag stig_id: 'GEN000460'
  tag gtitle: 'SRG-OS-000021'
  tag fix_id: 'F-21782r488277_fix'
  tag 'documentable'
  tag legacy: ['V-766', 'SV-39815']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
