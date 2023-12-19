control 'SV-37199' do
  title 'All network services daemon files must not have extended ACLs.'
  desc 'Restricting permission on daemons will protect them from unauthorized modification and possible system compromise.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /usr/sbin/*'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22313'
  tag rid: 'SV-37199r1_rule'
  tag stig_id: 'GEN001190'
  tag gtitle: 'GEN001190'
  tag fix_id: 'F-23542r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
