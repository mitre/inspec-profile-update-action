control 'SV-37349' do
  title "The root user's home directory must not be the root directory (/)."
  desc "Changing the root home directory to something other than / and assigning it a 0700 protection makes it more difficult for intruders to manipulate the system by reading the files root places in its default directory. It also gives root the same discretionary access control for root's home directory as for the other user home directories."
  desc 'check', %q(Determine if root is assigned a home directory other than / by listing its home directory.

Procedure:
# awk -F: '($1 == "root") { print $6 }' /etc/passwd

If the root user home directory is /, this is a finding.)
  desc 'fix', 'The root home directory should be something other than / (such as /roothome).

Procedure:
# mkdir /rootdir
# chown root /rootdir
# chgrp root /rootdir
# chmod 700 /rootdir
# cp -r /.??* /rootdir/.

Then, edit the passwd file and change the root home directory to /rootdir. The cp -r /.??* command copies all files and subdirectories of file names beginning with "." into the new root directory, which preserves the previous root environment. Ensure you are in the "/" directory when executing the "cp" command.'
  impact 0.3
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36040r2_chk'
  tag severity: 'low'
  tag gid: 'V-774'
  tag rid: 'SV-37349r2_rule'
  tag stig_id: 'GEN000900'
  tag gtitle: 'GEN000900'
  tag fix_id: 'F-31284r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
