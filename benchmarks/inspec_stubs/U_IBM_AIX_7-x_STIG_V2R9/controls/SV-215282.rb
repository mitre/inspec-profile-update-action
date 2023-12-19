control 'SV-215282' do
  title 'The AIX /etc/group file must have mode 0644 or less permissive.'
  desc 'The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'Verify the "/etc/group" file has the mode "0644" using command: 
# ls -l /etc/group 

The above command should yield the following output:
-rw-r--r--    1 root     security        387 Sep 06 11:40 /etc/group

If the file does not have mode "0644" or less permissive, this is a finding.'
  desc 'fix', 'Change the mode of the "/etc/group" file to "0644": 
# chmod 0644 /etc/group'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16480r294297_chk'
  tag severity: 'medium'
  tag gid: 'V-215282'
  tag rid: 'SV-215282r508663_rule'
  tag stig_id: 'AIX7-00-002091'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16478r294298_fix'
  tag 'documentable'
  tag legacy: ['SV-101713', 'V-91615']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
