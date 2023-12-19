control 'SV-39506' do
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
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-615r2_chk'
  tag severity: 'high'
  tag gid: 'V-833'
  tag rid: 'SV-39506r1_rule'
  tag stig_id: 'GEN004400'
  tag gtitle: 'GEN004400'
  tag fix_id: 'F-987r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
