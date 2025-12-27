control 'SV-227869' do
  title 'All .Xauthority files must have mode 0600 or less permissive.'
  desc '.Xauthority files ensure the user is authorized to access the specific X Windows host.  Excessive permissions may permit unauthorized modification of these files, which could lead to Denial of Service to authorized access or allow unauthorized access to be obtained.'
  desc 'check', 'Check the file permissions for the .Xauthority files in the home directories of users of X.

Procedure:
# cd ~<X user>
# ls -lL .Xauthority

If the file mode is more permissive than 0600, this is finding.'
  desc 'fix', 'Change the mode of the .Xauthority files.

Procedure:
# chmod 0600 .Xauthority'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30031r490003_chk'
  tag severity: 'medium'
  tag gid: 'V-227869'
  tag rid: 'SV-227869r603266_rule'
  tag stig_id: 'GEN005180'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30019r490004_fix'
  tag 'documentable'
  tag legacy: ['V-12014', 'SV-12515']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
