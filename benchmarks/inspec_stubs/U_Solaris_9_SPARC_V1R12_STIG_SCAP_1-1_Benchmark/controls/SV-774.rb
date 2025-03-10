control 'SV-774' do
  title "The root user's home directory must not be the root directory (/)."
  desc "Changing the root home directory to something other than / and assigning it a 0700 protection makes it more difficult for intruders to manipulate the system by reading the files that root places in its default directory. It also gives root the same discretionary access control for root's home directory as for the other plain user home directories."
  desc 'fix', 'The root home directory should be something other than / (such as /rootdir).

Procedure:
# mkdir /rootdir
# chown root /rootdir
# chgrp root /rootdir
# chmod 700 /rootdir
# cp -r /.??* /rootdir

Edit the passwd file and change the root home directory to /rootdir. The cp -r /.??* command copies all files and subdirectories of file names beginning with "." into the new root directory, which preserves the previous root environment. The cp command must be executed from the / directory.'
  impact 0.3
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'low'
  tag gid: 'V-774'
  tag rid: 'SV-774r2_rule'
  tag stig_id: 'GEN000900'
  tag gtitle: 'GEN000900'
  tag fix_id: 'F-928r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
