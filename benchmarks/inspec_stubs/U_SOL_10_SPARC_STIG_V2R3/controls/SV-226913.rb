control 'SV-226913' do
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
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29075r485026_chk'
  tag severity: 'medium'
  tag gid: 'V-226913'
  tag rid: 'SV-226913r854432_rule'
  tag stig_id: 'GEN003780'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29063r485027_fix'
  tag 'documentable'
  tag legacy: ['V-824', 'SV-824']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
