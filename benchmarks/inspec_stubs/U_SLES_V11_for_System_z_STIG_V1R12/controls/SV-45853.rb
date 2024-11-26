control 'SV-45853' do
  title 'Files executed through a mail aliases file must have mode 0755 or less permissive.'
  desc 'If a file executed through a mail aliases file has permissions greater than 0755, it can be modified by an unauthorized user and may contain malicious code or instructions potentially compromising the system.'
  desc 'check', 'If the “sendmail” package is not installed, this is not applicable.

Examine the contents of the /etc/aliases file.

Procedure:
# more /etc/aliases
Examine the aliases file for any utilized directories or paths.

# ls -lL <file referenced from aliases>
Check the permissions for any paths referenced. 
If any file referenced from the aliases file has a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Use the chmod command to change the access permissions for files executed from the alias file. 
For example:
# chmod 0755 filename.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43151r2_chk'
  tag severity: 'medium'
  tag gid: 'V-834'
  tag rid: 'SV-45853r2_rule'
  tag stig_id: 'GEN004420'
  tag gtitle: 'GEN004420'
  tag fix_id: 'F-39237r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
