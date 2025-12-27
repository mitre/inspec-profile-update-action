control 'SV-850' do
  title 'Any X Windows host must write .Xauthority files.'
  desc '.Xauthority files ensure the user is authorized to access the specific X Windows host.  If .Xauthority files are not used, it may be possible to obtain unauthorized access to the X Windows host.'
  desc 'check', 'Check for .Xauthority files being utilized by looking for such files in the home directory of a user that uses X.

Procedure:
# cd ~someuser
# ls -la .Xauthority

If the .Xauthority file does not exist, ask the SA if the user is using X Windows. If the user is utilizing X Windows and the .Xauthority file does not exist, this is a finding.'
  desc 'fix', 'Ensure the X Windows host is configured to write .Xauthority files into user home directories. Edit the Xaccess file. Ensure the line that writes the .Xauthority file is uncommented.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-718r2_chk'
  tag severity: 'medium'
  tag gid: 'V-850'
  tag rid: 'SV-850r2_rule'
  tag stig_id: 'GEN005160'
  tag gtitle: 'GEN005160'
  tag fix_id: 'F-1004r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-1, ECCD-2'
  tag cci: ['CCI-000297']
  tag nist: ['CM-2 b 2']
end
