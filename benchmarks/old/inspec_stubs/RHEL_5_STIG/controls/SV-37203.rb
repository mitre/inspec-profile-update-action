control 'SV-37203' do
  title 'The system must disable accounts after three consecutive unsuccessful login attempts.'
  desc 'Disabling accounts after a limited number of unsuccessful login attempts improves protection against password guessing attacks.'
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
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-766'
  tag rid: 'SV-37203r1_rule'
  tag stig_id: 'GEN000460'
  tag gtitle: 'GEN000460'
  tag fix_id: 'F-31153r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLO-1, ECLO-2'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
