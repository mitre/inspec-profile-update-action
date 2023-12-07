control 'SV-37426' do
  title 'The services file must have mode 0644 or less permissive.'
  desc 'The services file is critical to the proper operation of network services and must be protected from unauthorized modification.  Unauthorized modification could result in the failure of network services.'
  desc 'fix', 'Change the mode of the services file to 0644 or less permissive.

Procedure:
# chmod 0644 /etc/services'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-824'
  tag rid: 'SV-37426r1_rule'
  tag stig_id: 'GEN003780'
  tag gtitle: 'GEN003780'
  tag fix_id: 'F-31353r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
