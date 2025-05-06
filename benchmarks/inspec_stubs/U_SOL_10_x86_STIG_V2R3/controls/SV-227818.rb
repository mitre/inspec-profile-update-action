control 'SV-227818' do
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
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29980r489811_chk'
  tag severity: 'medium'
  tag gid: 'V-227818'
  tag rid: 'SV-227818r854497_rule'
  tag stig_id: 'GEN003780'
  tag gtitle: 'SRG-OS-000312'
  tag fix_id: 'F-29968r489812_fix'
  tag 'documentable'
  tag legacy: ['V-824', 'SV-824']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
