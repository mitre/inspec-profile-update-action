control 'SV-218537' do
  title 'Files executed through a mail aliases file must have mode 0755 or less permissive.'
  desc 'If a file executed through a mail aliases file has permissions greater than 0755, it can be modified by an unauthorized user and may contain malicious code or instructions potentially compromising the system.'
  desc 'check', 'If the "sendmail" package is not installed, this is not applicable.

Examine the contents of the /etc/aliases file.

Procedure:
# more /etc/aliases
Examine the aliases file for any referenced programs, which are specified with the pipe (|) symbol.

# ls -lL <file referenced from aliases>

Check the permissions for any paths referenced.
 
If any file referenced from the aliases file has a mode more permissive than 0755, this is a finding.'
  desc 'fix', 'Use the chmod command to change the access permissions for files executed from the alias file. 

For example:
# chmod 0755 filename'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20012r562732_chk'
  tag severity: 'medium'
  tag gid: 'V-218537'
  tag rid: 'SV-218537r603259_rule'
  tag stig_id: 'GEN004420'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20010r562733_fix'
  tag 'documentable'
  tag legacy: ['V-834', 'SV-63739']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
