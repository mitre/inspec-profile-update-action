control 'SV-209012' do
  title 'The system must prohibit the reuse of passwords within five iterations.'
  desc 'Preventing reuse of previous passwords helps ensure that a compromised password is not reused by a user.'
  desc 'check', 'To verify the password reuse setting is compliant, run the following command: 

# grep remember /etc/pam.d/system-auth /etc/pam.d/password-auth

The output must be a line beginning with "password required pam_pwhistory.so" and ending with "remember=5".

If the line is commented out, the line does not contain the specified elements, or the value for "remember" is less than “5”, this is a finding.'
  desc 'fix', 'Do not allow users to reuse recent passwords. This can be accomplished by using the "remember" option for the "pam_pwhistory" PAM module. In the file "/etc/pam.d/system-auth", append "remember=5" to the line which refers to the "pam_pwhistory.so" module, as shown: 

password required pam_pwhistory.so [existing_options] remember=5

The DoD requirement is five passwords.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-9265r357821_chk'
  tag severity: 'medium'
  tag gid: 'V-209012'
  tag rid: 'SV-209012r793733_rule'
  tag stig_id: 'OL6-00-000274'
  tag gtitle: 'SRG-OS-000077'
  tag fix_id: 'F-9265r357822_fix'
  tag 'documentable'
  tag legacy: ['V-50855', 'SV-65061']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
