control 'SV-37438' do
  title 'The services file must not have an extended ACL.'
  desc 'The services file is critical to the proper operation of network services and must be protected from unauthorized modification.  If the services file has an extended ACL, it may be possible for unauthorized users to modify the file.  Unauthorized modification could result in the failure of network services.'
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/services'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22428'
  tag rid: 'SV-37438r1_rule'
  tag stig_id: 'GEN003790'
  tag gtitle: 'GEN003790'
  tag fix_id: 'F-31356r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
