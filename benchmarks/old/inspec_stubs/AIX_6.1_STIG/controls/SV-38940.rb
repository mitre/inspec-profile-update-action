control 'SV-38940' do
  title "The root user's home directory must not be the root directory (/)."
  desc "Changing the root home directory to something other than / and assigning it a 0700 protection makes it more difficult for intruders to manipulate the system by reading the files that root places in its default directory. It also gives root the same discretionary access control for root's home directory as for the other plain user home directories."
  desc 'check', %q(Determine if root is assigned a home directory other than / by listing its home directory.

Procedure:
# grep "^root" /etc/passwd | awk -F":" '{print $6}'

If the root user home directory is /, this is a finding.)
  desc 'fix', 'The root home directory should be something other than / (such as /root).

Procedure:
# mkdir /root
# chown root /root
# chgrp sys /root
# chmod 700 /root
# cp -r /.??* /root/.

Then, edit the passwd file and change the root home directory to /root. The cp -r /.??* command copies all files and subdirectories of file names that begin with "." into the new root directory, which preserves the previous root environment. Must be in the "/" directory when executing the "cp" command.'
  impact 0.3
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28062r1_chk'
  tag severity: 'low'
  tag gid: 'V-774'
  tag rid: 'SV-38940r1_rule'
  tag stig_id: 'GEN000900'
  tag gtitle: 'GEN000900'
  tag fix_id: 'F-32113r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
