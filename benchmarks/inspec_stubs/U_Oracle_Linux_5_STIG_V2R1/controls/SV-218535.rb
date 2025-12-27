control 'SV-218535' do
  title 'Files executed through a mail aliases file must be owned by root and must reside within a directory owned and writable only by root.'
  desc 'If a file executed through a mail aliases file is not owned and writable only by root, it may be subject to unauthorized modification.  Unauthorized modification of files executed through aliases may allow unauthorized users to attain root privileges.'
  desc 'check', 'Verify the ownership of files referenced within the sendmail aliases file.

Procedure:
# more /etc/aliases
Examine the aliases file for any utilized directories or paths.

# ls -lL <directory or file path>

Check the owner for any paths referenced.
 
Check if the file or parent directory is owned by root. If not, this is a finding.'
  desc 'fix', 'Edit the /etc/aliases file (alternatively, /usr/lib/sendmail.cf). Locate the entries executing a program. They will appear similar to the following line:

Aliasname: : /usr/local/bin/ls (or some other program name)

Ensure root owns the programs and the directory(ies) they reside in by using the chown command to change owner to root.

Procedure:
# chown root <file or directory name>'
  impact 0.7
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20010r562726_chk'
  tag severity: 'high'
  tag gid: 'V-218535'
  tag rid: 'SV-218535r603259_rule'
  tag stig_id: 'GEN004400'
  tag gtitle: 'SRG-OS-000138-GPOS-00069'
  tag fix_id: 'F-20008r562727_fix'
  tag 'documentable'
  tag legacy: ['V-833', 'SV-63699']
  tag cci: ['CCI-000225', 'CCI-001090']
  tag nist: ['AC-6', 'SC-4']
end
