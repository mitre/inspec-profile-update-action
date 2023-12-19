control 'SV-226471' do
  title "The root user's home directory must not be the root directory (/)."
  desc "Changing the root home directory to something other than / and assigning it a 0700 protection makes it more difficult for intruders to manipulate the system by reading the files that root places in its default directory. It also gives root the same discretionary access control for root's home directory as for the other plain user home directories."
  desc 'check', %q(Determine if root is assigned a home directory other than / by listing its home directory.

Procedure:
# grep "^root" /etc/passwd | awk -F":" '{print $6}'

If the root user home directory is /, this is a finding.)
  desc 'fix', 'The root home directory should be something other than / (such as /rootdir).

Procedure:
# mkdir /rootdir
# chown root /rootdir
# chgrp root /rootdir
# chmod 700 /rootdir
# cp -r /.??* /rootdir

Edit the passwd file and change the root home directory to /rootdir. The cp -r /.??* command copies all files and subdirectories of file names beginning with "." into the new root directory, which preserves the previous root environment. The cp command must be executed from the / directory.'
  impact 0.3
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-36382r602749_chk'
  tag severity: 'low'
  tag gid: 'V-226471'
  tag rid: 'SV-226471r603265_rule'
  tag stig_id: 'GEN000900'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-36346r602750_fix'
  tag 'documentable'
  tag legacy: ['SV-774', 'V-774']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
