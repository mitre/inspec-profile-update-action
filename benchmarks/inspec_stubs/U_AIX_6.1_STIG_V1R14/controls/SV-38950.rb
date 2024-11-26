control 'SV-38950' do
  title 'The services file must not have an extended ACL.'
  desc 'The services file is critical to the proper operation of network services and must be protected from unauthorized modification.  If the services file has an extended ACL, it may be possible for unauthorized users to modify the file.  Unauthorized modification could result in the failure of network services.'
  desc 'check', 'Check the permissions of the /etc/services file.

#aclget /etc/services
Check if extended permissions are disabled.  If extended permissions are not disabled, this is a finding.'
  desc 'fix', 'Remove the extended ACL from the services file and disable extended permissions.

#acledit /etc/services'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-38107r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22428'
  tag rid: 'SV-38950r1_rule'
  tag stig_id: 'GEN003790'
  tag gtitle: 'GEN003790'
  tag fix_id: 'F-31826r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
