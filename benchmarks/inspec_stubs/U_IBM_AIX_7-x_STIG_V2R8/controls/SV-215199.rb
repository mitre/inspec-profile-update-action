control 'SV-215199' do
  title 'The AIX root accounts home directory must not have an extended ACL.'
  desc 'Excessive permissions on root home directories allow unauthorized access to root user files.'
  desc 'check', %q(Verify the "root" account's home directory has no extended ACL using command:

# aclget ~root 
*
* ACL_type   AIXC
*
attributes:
base permissions
    owner(root):  rwx
    group(system):  ---
    others:  ---
extended permissions
    disabled

If extended permissions are enabled, the directory has an extended ACL, and this is a finding.)
  desc 'fix', %q(Remove the extended ACL from the "root" account's home directory using command:
# acledit ~root 

Change extended attributes to disabled.)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16397r294048_chk'
  tag severity: 'medium'
  tag gid: 'V-215199'
  tag rid: 'SV-215199r508663_rule'
  tag stig_id: 'AIX7-00-001040'
  tag gtitle: 'SRG-OS-000480-GPOS-00230'
  tag fix_id: 'F-16395r294049_fix'
  tag 'documentable'
  tag legacy: ['SV-101863', 'V-91765']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
