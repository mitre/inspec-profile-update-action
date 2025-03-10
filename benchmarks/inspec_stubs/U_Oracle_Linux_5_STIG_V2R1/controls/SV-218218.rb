control 'SV-218218' do
  title 'The system must disable accounts after three consecutive unsuccessful login attempts.'
  desc 'Disabling accounts after a limited number of unsuccessful login attempts improves protection against password guessing attacks.'
  desc 'check', 'Check the pam_tally configuration.
# more /etc/pam.d/system-auth 
Confirm the following line is configured, before any "auth sufficient" lines:
auth required pam_tally2.so deny=3 
If no such line is found, this is a finding.'
  desc 'fix', 'By default link /etc/pam.d/system-auth points to /etc/pam.d/system-auth-ac which is the file maintained by the authconfig utility. In order to add pam options other than those available via the utility create /etc/pam.d/system-auth-local with the options and including system-auth-ac. In order to set the account lockout to three failed attempts the content should be similar to:

auth required pam_access.so
auth required pam_tally2.so deny=3
auth include system-auth-ac
account required pam_tally2.so
account include system-auth-ac
password include system-auth-ac
session include system-auth-ac

Once system-auth-local is written reset the /etc/pam.d/system-auth to point to system-auth-local. This is necessary because authconfig writes directly to system-auth-ac so any changes made by hand will be lost if authconfig is run.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19693r553991_chk'
  tag severity: 'medium'
  tag gid: 'V-218218'
  tag rid: 'SV-218218r603259_rule'
  tag stig_id: 'GEN000460'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag fix_id: 'F-19691r553992_fix'
  tag 'documentable'
  tag legacy: ['V-766', 'SV-63383']
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
