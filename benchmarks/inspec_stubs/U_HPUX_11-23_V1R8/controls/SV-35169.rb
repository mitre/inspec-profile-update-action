control 'SV-35169' do
  title 'Files executed through a mail aliases file must be owned by root and must reside within a directory owned and writable only by root.'
  desc 'If a file executed through a mail aliases file is not owned and writable only by root, it may be subject to unauthorized modification. Unauthorized modification of files executed through aliases may allow unauthorized users to attain root privileges.'
  desc 'check', 'Examine the aliases file for any utilized directories or paths.
# cat/etc/mail/aliases | cut -f 2,2 -d ":" | grep "|"

For example, the alias file entry will look like:
msgs: "|/usr/bin/msgs -s"

The entry must be an absolute path name:
# ls -lLd `dirname <entry>`
# ls -lL <entry>

If the file or parent directory is not owned by root, this a finding.'
  desc 'fix', 'Edit the /etc/mail/aliases file Locate the entries executing a program. 
They will appear similar to the following line:

alias: "|/usr/local/bin/ls" (or some other program name)

Ensure root owns the programs and the directory(ies) they reside in by using the chown command to change owner to root.
For a directory entry:
# chown root <entry>

For a file entry (change BOTH the directory and file, where/as necessary:
# chown root <entry>
# chown root `dirname <entry>`'
  impact 0.7
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-35019r1_chk'
  tag severity: 'high'
  tag gid: 'V-833'
  tag rid: 'SV-35169r1_rule'
  tag stig_id: 'GEN004400'
  tag gtitle: 'GEN004400'
  tag fix_id: 'F-30312r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
