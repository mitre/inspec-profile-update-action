control 'SV-226914' do
  title 'The services file must not have an extended ACL.'
  desc 'The services file is critical to the proper operation of network services and must be protected from unauthorized modification.  If the services file has an extended ACL, it may be possible for unauthorized users to modify the file.  Unauthorized modification could result in the failure of network services.'
  desc 'check', 'Check the permissions of the /etc/services file.
# ls -lL /etc/services
If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- /etc/services'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29076r485029_chk'
  tag severity: 'medium'
  tag gid: 'V-226914'
  tag rid: 'SV-226914r603265_rule'
  tag stig_id: 'GEN003790'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29064r485030_fix'
  tag 'documentable'
  tag legacy: ['V-22428', 'SV-26660']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
