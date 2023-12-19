control 'SV-824' do
  title 'The services file must have mode 0444 or less permissive.'
  desc 'The services file is critical to the proper operation of network services and must be protected from unauthorized modification.  Unauthorized modification could result in the failure of network services.'
  desc 'check', 'Check the mode of the services file.

Procedure:
# ls -lL /etc/services

If the services file has a mode more permissive than 0444, this is a finding.'
  desc 'fix', 'Change the mode of the services file to 0444 or less permissive.

Procedure:
# chmod 0444 /etc/services'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-8030r2_chk'
  tag severity: 'medium'
  tag gid: 'V-824'
  tag rid: 'SV-824r2_rule'
  tag stig_id: 'GEN003780'
  tag gtitle: 'GEN003780'
  tag fix_id: 'F-978r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
