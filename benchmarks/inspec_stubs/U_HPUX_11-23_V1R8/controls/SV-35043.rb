control 'SV-35043' do
  title 'Files executed through a mail aliases file must have mode 0755 or less permissive.'
  desc 'If a file executed through a mail alias file has permissions greater than 0755, it can be modified by an unauthorized user and may contain malicious code or instructions possibly compromising the system.'
  desc 'check', 'Examine the aliases file on the system for any utilized directories or paths.
# cat /etc/mail/aliases | cut -f 2,2 -d ":" | grep "|" 

Check the permissions for any file paths referenced. 
# ls -lL <path/file>

If any file referenced from the aliases file has a mode more 
permissive than 0755, this is a finding.'
  desc 'fix', 'Use the chmod command to change the access permissions 
for files executed from the aliases file. For example:
# chmod 0755 <path/file>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36562r1_chk'
  tag severity: 'medium'
  tag gid: 'V-834'
  tag rid: 'SV-35043r1_rule'
  tag stig_id: 'GEN004420'
  tag gtitle: 'GEN004420'
  tag fix_id: 'F-31930r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
