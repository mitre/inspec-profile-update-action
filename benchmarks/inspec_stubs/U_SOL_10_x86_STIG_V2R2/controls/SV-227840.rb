control 'SV-227840' do
  title 'Files executed through a mail aliases file must be owned by root and must reside within a directory owned and writable only by root.'
  desc 'If a file executed through a mail aliases file is not owned and writable only by root, it may be subject to unauthorized modification.  Unauthorized modification of files executed through aliases may allow unauthorized users to attain root privileges.'
  desc 'check', 'Find the aliases file on the system.

Procedure:
# find / -name aliases -depth -print
# more < aliases file location >

Examine the aliases file for any directories or paths that may be utilized.

Procedure:
# ls -lL < path >

Check if the file or parent directory is owned by root.  If not, this is a finding.'
  desc 'fix', 'Edit the /etc/mail/aliases file (alternatively, /usr/lib/sendmail.cf).  Locate the entries executing a program.  They will appear similar to the following line.

Aliasname: : /usr/local/bin/ls (or some other program name)

Ensure root owns the programs and the directory(ies) they reside in by using the chown command to change owner to root.
Procedure:
# chown root filename'
  impact 0.7
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-36472r603019_chk'
  tag severity: 'high'
  tag gid: 'V-227840'
  tag rid: 'SV-227840r603266_rule'
  tag stig_id: 'GEN004400'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-36436r603020_fix'
  tag 'documentable'
  tag legacy: ['V-833', 'SV-833']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
