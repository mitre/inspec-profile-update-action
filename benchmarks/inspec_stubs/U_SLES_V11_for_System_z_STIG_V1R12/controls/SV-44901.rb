control 'SV-44901' do
  title 'The root users home directory must not be the root directory (/).'
  desc "Changing the root home directory to something other than / and assigning it a 0700 protection makes it more difficult for intruders to manipulate the system by reading the files root places in its default directory. It also gives root the same discretionary access control for root's home directory as for the other user home directories."
  desc 'check', %q(Determine if root is assigned a home directory other than / by listing its home directory.

Procedure:
# grep "^root" /etc/passwd | awk -F":" '{print $6}'

If the root user home directory is /, this is a finding.)
  desc 'fix', 'The root home directory should be something other than / (such as /roothome).

Procedure:
# mkdir /rootdir
# chown root /rootdir
# chgrp root /rootdir
# chmod 700 /rootdir
# cp -r /.??* /rootdir/.

Then, edit the passwd file and change the root home directory to /rootdir. The cp -r /.??* command copies all files and subdirectories of file names beginning with "." into the new root directory, which preserves the previous root environment. Ensure you are in the "/" directory when executing the "cp" command.   
_ OR

Use the YaST ‘Security and Users’ > ‘User and Group Management’ module to update the home directory for root.'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-42341r1_chk'
  tag severity: 'low'
  tag gid: 'V-774'
  tag rid: 'SV-44901r1_rule'
  tag stig_id: 'GEN000900'
  tag gtitle: 'GEN000900'
  tag fix_id: 'F-38333r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
