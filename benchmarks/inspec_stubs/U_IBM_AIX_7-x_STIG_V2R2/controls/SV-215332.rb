control 'SV-215332' do
  title 'The AIX user home directories must not have extended ACLs.'
  desc 'Excessive permissions on home directories allow unauthorized access to user files.'
  desc 'check', 'Verify user home directories have no extended ACLs using command: 

# cat /etc/passwd | cut -f 6,6 -d ":" | xargs -n1 aclget 
*
* ACL_type   AIXC
*
attributes:
base permissions
    owner(root):  rwx
    group(system):  r-x
    others:  r---
extended permissions
    disabled

If extended permissions are not disabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the user home directory and disable extended permissions: 
# acledit <directory>'
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16530r294447_chk'
  tag severity: 'medium'
  tag gid: 'V-215332'
  tag rid: 'SV-215332r508663_rule'
  tag stig_id: 'AIX7-00-003019'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-16528r294448_fix'
  tag 'documentable'
  tag legacy: ['SV-101865', 'V-91767']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
