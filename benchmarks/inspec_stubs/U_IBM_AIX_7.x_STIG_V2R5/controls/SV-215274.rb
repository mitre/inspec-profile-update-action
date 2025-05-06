control 'SV-215274' do
  title 'The AIX /etc/group file must be owned by root.'
  desc 'The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'Verify the "/etc/group" file is owned by "root" using command: 
# ls -l /etc/group 

The above command should yield the following output:
-rw-r--r--    1 root     security        387 Sep 06 11:40 /etc/group

If the file is not owned by "root", this is a finding.'
  desc 'fix', 'Change the owner of the "/etc/group" file to "root": 
# chown root /etc/group'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16472r294273_chk'
  tag severity: 'medium'
  tag gid: 'V-215274'
  tag rid: 'SV-215274r508663_rule'
  tag stig_id: 'AIX7-00-002083'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16470r294274_fix'
  tag 'documentable'
  tag legacy: ['SV-101709', 'V-91611']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
