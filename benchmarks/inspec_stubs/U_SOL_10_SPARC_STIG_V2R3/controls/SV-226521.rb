control 'SV-226521' do
  title 'The /etc/group file must not have an extended ACL.'
  desc 'The /etc/group file is critical to system security and must be protected from unauthorized modification.  The group file contains a list of system groups and associated information.'
  desc 'check', 'Verify /etc/group has no extended ACL.
# ls -l /etc/group
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/group'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-28682r482951_chk'
  tag severity: 'medium'
  tag gid: 'V-226521'
  tag rid: 'SV-226521r603265_rule'
  tag stig_id: 'GEN001394'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-28670r482952_fix'
  tag 'documentable'
  tag legacy: ['V-22338', 'SV-26436']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
