control 'SV-218571' do
  title 'All .Xauthority files must have mode 0600 or less permissive.'
  desc '.Xauthority files ensure the user is authorized to access specific X Windows host. Excessive permissions may permit unauthorized modification of these files, which could lead to Denial of Service to authorized access or allow unauthorized access to be obtained.'
  desc 'check', 'Check the file permissions for the .Xauthority files.

Procedure:
# ls -la |egrep "(\\.Xauthority|\\.xauth)"

If the file mode is more permissive than 0600, this is finding.'
  desc 'fix', 'Change the mode of the .Xauthority files.

Procedure:
# chmod 0600 .Xauthority'
  impact 0.5
  ref 'DPMS Target Oracle Linux 5'
  tag check_id: 'C-20046r562801_chk'
  tag severity: 'medium'
  tag gid: 'V-218571'
  tag rid: 'SV-218571r603259_rule'
  tag stig_id: 'GEN005180'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-20044r562802_fix'
  tag 'documentable'
  tag legacy: ['V-12014', 'SV-63205']
  tag cci: ['CCI-000366', 'CCI-000225']
  tag nist: ['CM-6 b', 'AC-6']
end
