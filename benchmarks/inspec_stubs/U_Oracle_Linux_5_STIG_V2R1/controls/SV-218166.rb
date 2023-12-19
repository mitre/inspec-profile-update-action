control 'SV-218166' do
  title 'The /etc/gshadow file must not have an extended ACL.'
  desc 'The /etc/gshadow file is critical to system security and must be protected from unauthorized modification.   The /etc/gshadow file contains a list of system groups and hashes for group passwords.'
  desc 'check', "Check  /etc/gshadow has no extended ACL.
# ls -l /etc/gshadow
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/gshadow'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19641r561458_chk'
  tag severity: 'medium'
  tag gid: 'V-218166'
  tag rid: 'SV-218166r603259_rule'
  tag stig_id: 'GEN000000-LNX001434'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19639r561459_fix'
  tag 'documentable'
  tag legacy: ['V-22344', 'SV-62711']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
