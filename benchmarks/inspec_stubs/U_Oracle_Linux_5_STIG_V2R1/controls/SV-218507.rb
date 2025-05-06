control 'SV-218507' do
  title 'The services file must have mode 0644 or less permissive.'
  desc 'The services file is critical to the proper operation of network services and must be protected from unauthorized modification.  Unauthorized modification could result in the failure of network services.'
  desc 'check', 'Check the mode of the services file.

Procedure:
# ls -lL /etc/services

If the services file has a mode more permissive than 0644, this is a finding.'
  desc 'fix', 'Change the mode of the services file to 0644 or less permissive.

Procedure:
# chmod 0644 /etc/services'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19982r562654_chk'
  tag severity: 'medium'
  tag gid: 'V-218507'
  tag rid: 'SV-218507r603259_rule'
  tag stig_id: 'GEN003780'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19980r562655_fix'
  tag 'documentable'
  tag legacy: ['V-824', 'SV-63983']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
