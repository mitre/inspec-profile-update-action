control 'SV-38814' do
  title 'The .Xauthority files must not have extended ACLs.'
  desc '.Xauthority files ensure the user is authorized to access that specific X Windows host.  Extended ACLs may permit unauthorized modification of these files, which could lead to Denial of Service to authorized access or allow unauthorized access to be obtained.'
  desc 'check', 'Get a list of (non-system account) users and the associated home directories. 
# cat /etc/passwd | cut -f 1,6 -d ":" 
Check the file permissions for the user .Xauthority files.

#aclget .Xauthority
Check if extended permissions are disabled.  If extended permissions are not disabled,  this is a finding.'
  desc 'fix', 'Remove the extended ACL from the .Xauthority file(s) and disable extended permissions.

#acledit .Xauthority'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37054r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22446'
  tag rid: 'SV-38814r1_rule'
  tag stig_id: 'GEN005190'
  tag gtitle: 'GEN005190'
  tag fix_id: 'F-32322r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
