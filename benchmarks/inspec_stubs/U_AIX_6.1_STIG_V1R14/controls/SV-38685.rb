control 'SV-38685' do
  title 'All network services daemon files must not have extended ACLs.'
  desc 'Restricting permission on daemons will protect them from unauthorized modification and possible system compromise.'
  desc 'check', 'Verify network services daemon files have no extended ACLs. 
# aclget <directory>/<network service daemon> 
NOTE: Network daemons that may not reside in these directories (such as httpd or sshd) must also be checked for extended ACLs.
If any of the service daemons have extended attributes enabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL(s) from the network service daemon file(s).
#acledit < directory >/< network service daemon >
Disable extended permissions.'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-36946r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22313'
  tag rid: 'SV-38685r1_rule'
  tag stig_id: 'GEN001190'
  tag gtitle: 'GEN001190'
  tag fix_id: 'F-32210r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
