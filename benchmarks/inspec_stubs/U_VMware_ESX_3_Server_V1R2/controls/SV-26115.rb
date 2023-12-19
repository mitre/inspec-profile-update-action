control 'SV-26115' do
  title 'The .Xauthority files must not have extended ACLs.'
  desc '.Xauthority files ensure the user is authorized to access the specific X Windows host.  Extended ACLs may permit unauthorized modification of these files, which could lead to Denial-of-Service to authorized access or allow unauthorized access to be obtained.'
  desc 'check', 'Check the file permissions for the .Xauthority files.
# ls -lL .Xauthority
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the .Xauthority file(s).'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-27716r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22446'
  tag rid: 'SV-26115r1_rule'
  tag stig_id: 'GEN005190'
  tag gtitle: 'GEN005190'
  tag fix_id: 'F-26291r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
