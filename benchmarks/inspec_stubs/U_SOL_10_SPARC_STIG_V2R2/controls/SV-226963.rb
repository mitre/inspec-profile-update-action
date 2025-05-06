control 'SV-226963' do
  title 'The .Xauthority files must not have extended ACLs.'
  desc '.Xauthority files ensure the user is authorized to access the specific X Windows host.  Extended ACLs may permit unauthorized modification of these files, which could lead to Denial of Service to authorized access or allow unauthorized access to be obtained.'
  desc 'check', 'Check the file permissions for the .Xauthority files.
# ls -lL .Xauthority
If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.
# chmod A- .Xauthority'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29125r485219_chk'
  tag severity: 'medium'
  tag gid: 'V-226963'
  tag rid: 'SV-226963r603265_rule'
  tag stig_id: 'GEN005190'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29113r485220_fix'
  tag 'documentable'
  tag legacy: ['V-22446', 'SV-26711']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
