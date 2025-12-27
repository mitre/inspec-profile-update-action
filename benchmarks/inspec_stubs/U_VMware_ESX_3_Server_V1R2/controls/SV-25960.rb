control 'SV-25960' do
  title 'All network services daemon files must not have extended ACLs.'
  desc 'Restricting permission on daemons will protect them from unauthorized modification and possible system compromise.'
  desc 'check', "Verify network services daemon files have no extended ACLs. 

# ls -la <network service daemon> 

If the permissions include a '+', the file has an extended ACL, this is a finding.

Note: Network daemons not residing in these directories must also be checked."
  desc 'fix', 'Remove the extended ACL(s) from the network service daemon file(s).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29098r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22313'
  tag rid: 'SV-25960r1_rule'
  tag stig_id: 'GEN001190'
  tag gtitle: 'GEN001190'
  tag fix_id: 'F-26098r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
