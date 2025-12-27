control 'SV-218508' do
  title 'The services file must not have an extended ACL.'
  desc 'The services file is critical to the proper operation of network services and must be protected from unauthorized modification.  If the services file has an extended ACL, it may be possible for unauthorized users to modify the file.  Unauthorized modification could result in the failure of network services.'
  desc 'check', "Check the permissions of the /etc/services file.
# ls -lL /etc/services
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/services'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-19983r562657_chk'
  tag severity: 'medium'
  tag gid: 'V-218508'
  tag rid: 'SV-218508r603259_rule'
  tag stig_id: 'GEN003790'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-19981r562658_fix'
  tag 'documentable'
  tag legacy: ['V-22428', 'SV-63985']
  tag cci: ['CCI-000225', 'CCI-001499']
  tag nist: ['AC-6', 'CM-5 (6)']
end
