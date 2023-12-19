control 'SV-216075' do
  title 'The .Xauthority files must not have extended ACLs.'
  desc '.Xauthority files ensure the user is authorized to access the specific X Windows host. Extended ACLs may permit unauthorized modification of these files, which could lead to Denial of Service to authorized access or allow unauthorized access to be obtained.'
  desc 'check', 'If X Display Manager (XDM) is not used on the system, this is not applicable.

Determine if XDM is running. 

Procedure:
# ps -ef | grep xdm

Check the file permissions for the .Xauthority files. 
# ls -lL .Xauthority

If the permissions include a "+", the file has an extended ACL and this is a finding.'
  desc 'fix', 'Remove the extended ACL from the file.

# chmod A- .Xauthority'
  impact 0.5
  ref 'DPMS Target Solaris 11 X86'
  tag check_id: 'C-17313r372607_chk'
  tag severity: 'medium'
  tag gid: 'V-216075'
  tag rid: 'SV-216075r603268_rule'
  tag stig_id: 'SOL-11.1-020520'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17311r372608_fix'
  tag 'documentable'
  tag legacy: ['V-61023', 'SV-75491']
  tag cci: ['CCI-000225', 'CCI-000366']
  tag nist: ['AC-6', 'CM-6 b']
end
