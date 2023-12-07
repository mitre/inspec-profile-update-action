control 'SV-834' do
  title 'Files executed through a mail aliases file must have mode 0755 or less permissive.'
  desc 'If a file executed through a mail alias file has permissions greater than 0755, it can be modified by an unauthorized user and may contain malicious code or instructions possibly compromising the system.'
  desc 'check', 'Find the aliases file on the system.
Procedure:
# find / -name aliases -depth -print

Examine the aliases file for any directories or paths that may be utilized.
Procedure:
# more <aliases file location>

Check the permissions for any paths referenced.
Procedure:
# ls -lL <path>

If any file referenced from the aliases file has a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Use the chmod command to change the access permissions for files executed from the alias file.
For example:

# chmod 0755 < filename >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-8033r2_chk'
  tag severity: 'medium'
  tag gid: 'V-834'
  tag rid: 'SV-834r2_rule'
  tag stig_id: 'GEN004420'
  tag gtitle: 'GEN004420'
  tag fix_id: 'F-988r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
