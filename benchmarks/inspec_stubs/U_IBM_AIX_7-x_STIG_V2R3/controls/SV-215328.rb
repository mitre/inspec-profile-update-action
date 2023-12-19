control 'SV-215328' do
  title 'The AIX /etc/group file must not have an extended ACL.'
  desc 'The "/etc/group" file contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'Check the ACL of the "/etc/group" file:
# aclget /etc/group 

The above command should yield the following output:
*
* ACL_type   AIXC
*
attributes: 
base permissions
    owner(root):  rw-
    group(security):  r--
    others:  r--
extended permissions
    disabled

If the extended ACL are not "disabled", this is a finding.'
  desc 'fix', 'Remove the extended ACL from the "/etc/group" using command: 
# acledit /etc/group'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16526r294435_chk'
  tag severity: 'medium'
  tag gid: 'V-215328'
  tag rid: 'SV-215328r508663_rule'
  tag stig_id: 'AIX7-00-003015'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-16524r294436_fix'
  tag 'documentable'
  tag legacy: ['V-91617', 'SV-101715']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
