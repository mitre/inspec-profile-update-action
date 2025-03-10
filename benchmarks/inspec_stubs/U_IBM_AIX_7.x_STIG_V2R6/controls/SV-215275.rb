control 'SV-215275' do
  title 'The AIX /etc/group file must be group-owned by security.'
  desc 'The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'Verify the "/etc/group" file is group-owned by "security" using command: 
# ls -l /etc/group 

The above command should yield the following output:
-rw-r--r--    1 root     security        387 Sep 06 11:40 /etc/group

If the file is not group-owned by "security", this is a finding.'
  desc 'fix', 'Change the group of the "/etc/group" file to "security": 
# chgrp security /etc/group'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16473r294276_chk'
  tag severity: 'medium'
  tag gid: 'V-215275'
  tag rid: 'SV-215275r508663_rule'
  tag stig_id: 'AIX7-00-002084'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16471r294277_fix'
  tag 'documentable'
  tag legacy: ['SV-101711', 'V-91613']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
