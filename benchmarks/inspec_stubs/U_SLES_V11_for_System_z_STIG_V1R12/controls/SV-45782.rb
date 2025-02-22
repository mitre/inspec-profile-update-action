control 'SV-45782' do
  title 'The services file must not have an extended ACL.'
  desc 'The services file is critical to the proper operation of network services and must be protected from unauthorized modification.  If the services file has an extended ACL, it may be possible for unauthorized users to modify the file.  Unauthorized modification could result in the failure of network services.'
  desc 'check', "Check the permissions of the /etc/services file.
# ls -lL /etc/services
If the permissions include a '+', the file has an extended ACL. If the file has an extended ACL and it has not been documented with the IAO, this is a finding."
  desc 'fix', 'Remove the extended ACL from the file.
# setfacl --remove-all /etc/services'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43120r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22428'
  tag rid: 'SV-45782r1_rule'
  tag stig_id: 'GEN003790'
  tag gtitle: 'GEN003790'
  tag fix_id: 'F-39177r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
