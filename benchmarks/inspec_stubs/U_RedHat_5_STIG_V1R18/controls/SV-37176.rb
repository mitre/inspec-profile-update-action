control 'SV-37176' do
  title 'The /etc/gshadow file must not have an extended ACL.'
  desc 'The /etc/gshadow file is critical to system security and must be protected from unauthorized modification.   The /etc/gshadow file contains a list of system groups and hashes for group passwords.'
  desc 'check', "Check  /etc/gshadow has no extended ACL.
# ls -l /etc/gshadow
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-35880r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22344'
  tag rid: 'SV-37176r1_rule'
  tag stig_id: 'GEN000000-LNX001434'
  tag gtitle: 'GEN000000-LNX001434'
  tag fix_id: 'F-31135r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
