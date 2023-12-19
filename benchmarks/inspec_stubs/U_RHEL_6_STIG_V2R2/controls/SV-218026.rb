control 'SV-218026' do
  title 'The system must prohibit the reuse of passwords within five iterations.'
  desc 'Preventing reuse of previous passwords helps ensure that a compromised password is not reused by a user.'
  desc 'check', 'To verify the password reuse setting is compliant, run the following command:

# grep remember /etc/pam.d/system-auth /etc/pam.d/password-auth

If the line is commented out, the line does not contain "password required pam_pwhistory.so" or "password requisite pam_pwhistory.so", or the value for "remember" is less than “5”, this is a finding.'
  desc 'fix', 'Do not allow users to reuse recent passwords. This can be accomplished by using the "remember" option for the "pam_pwhistory" PAM module. In the file "/etc/pam.d/system-auth" and /etc/pam.d/password-auth, append "remember=5" to the lines that refer to the "pam_pwhistory.so" module, as shown:

password required pam_pwhistory.so [existing_options] remember=5

or

password requisite pam_pwhistory.so [existing_options] remember=5

The DoD requirement is five passwords.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19507r462403_chk'
  tag severity: 'medium'
  tag gid: 'V-218026'
  tag rid: 'SV-218026r603264_rule'
  tag stig_id: 'RHEL-06-000274'
  tag gtitle: 'SRG-OS-000077'
  tag fix_id: 'F-19505r462404_fix'
  tag 'documentable'
  tag legacy: ['V-38658', 'SV-50459']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
