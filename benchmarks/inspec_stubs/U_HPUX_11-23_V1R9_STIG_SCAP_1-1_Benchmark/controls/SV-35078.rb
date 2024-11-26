control 'SV-35078' do
  title 'The services file must have mode 0444 or less permissive.'
  desc 'The services file is critical to the proper operation of network services and must be protected from unauthorized modification. Unauthorized modification could result in the failure of network services.'
  desc 'fix', 'Change the mode of the services file to 0444 or less permissive.
# chmod 0444 /etc/services'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag severity: 'medium'
  tag gid: 'V-824'
  tag rid: 'SV-35078r1_rule'
  tag stig_id: 'GEN003780'
  tag gtitle: 'GEN003780'
  tag fix_id: 'F-30247r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
