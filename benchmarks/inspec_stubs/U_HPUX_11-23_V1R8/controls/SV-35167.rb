control 'SV-35167' do
  title 'The .Xauthority files must not have extended ACLs.'
  desc '.Xauthority files ensure the user is authorized to access the specific X Windows host. Extended ACLs may permit unauthorized modification of these files, which could lead to Denial of Service to authorized access or allow unauthorized access to be obtained.'
  desc 'check', 'Get a list of (non-system account) users and the associated home directories.
# cat /etc/passwd | cut -f 1,6 -d ":" 

Check the file permissions for the user .Xauthority files.
# ls -lLa /<userhomedirectory>/.Xauthority

If the permissions include a "+", the file has an extended ACL, this is a finding.'
  desc 'fix', 'Remove the optional ACL from the file.
# chacl -z /<userhomedirectory>/.Xauthority'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36600r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22446'
  tag rid: 'SV-35167r1_rule'
  tag stig_id: 'GEN005190'
  tag gtitle: 'GEN005190'
  tag fix_id: 'F-31967r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
