control 'SV-38691' do
  title 'NIS/NIS+/yp command files must not have extended ACLs.'
  desc "NIS/NIS+/yp files are part of the system's identification and authentication processes and are, therefore, critical to system security. ACLs on these files could result in unauthorized modification, which could compromise these processes and the system."
  desc 'check', 'Determine if any NIS/NIS+/yp command files have an extended ACL. Check if extended permissions are disabled.

Procedure:

# aclget /var/nis  
# aclget /var/yp 
If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the NS/NIS+/yp command file(s) and disable extended permissions.

#acledit < directory >/< file >'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37005r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22318'
  tag rid: 'SV-38691r1_rule'
  tag stig_id: 'GEN001361'
  tag gtitle: 'GEN001361'
  tag fix_id: 'F-32268r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
