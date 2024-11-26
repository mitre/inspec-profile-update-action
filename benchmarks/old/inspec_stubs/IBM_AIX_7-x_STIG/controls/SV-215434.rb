control 'SV-215434' do
  title 'The AIX root user home directory must not be the root directory (/).'
  desc "Changing the root home directory to something other than / and assigning it a 0700 protection makes it more difficult for intruders to manipulate the system by reading the files that root places in its default directory. It also gives root the same discretionary access control for root's home directory as for the other plain user home directories."
  desc 'check', %q(Determine if root is assigned a home directory other than "/" by listing its home directory by running command: 

# grep "^root" /etc/passwd | awk -F":" '{print $6}' 
/root

If the root user's home directory is "/", this is a finding.)
  desc 'fix', 'The root home directory should be something other than "/" (such as /root). 

Run commands: 
# mkdir /root 
# chown root /root 
# chgrp system /root 
# chmod 700 /root 

Then, edit the passwd file and change the root home directory to "/root".'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16632r294753_chk'
  tag severity: 'medium'
  tag gid: 'V-215434'
  tag rid: 'SV-215434r508663_rule'
  tag stig_id: 'AIX7-00-003140'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-16630r294754_fix'
  tag 'documentable'
  tag legacy: ['V-91751', 'SV-101849']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
