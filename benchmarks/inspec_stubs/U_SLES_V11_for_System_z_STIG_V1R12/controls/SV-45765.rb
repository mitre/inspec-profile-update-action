control 'SV-45765' do
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
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43119r1_chk'
  tag severity: 'medium'
  tag gid: 'V-824'
  tag rid: 'SV-45765r1_rule'
  tag stig_id: 'GEN003780'
  tag gtitle: 'GEN003780'
  tag fix_id: 'F-39165r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
