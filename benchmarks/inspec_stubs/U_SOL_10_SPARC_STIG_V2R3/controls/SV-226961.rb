control 'SV-226961' do
  title 'Any X Windows host must write .Xauthority files.'
  desc '.Xauthority files ensure the user is authorized to access the specific X Windows host.  If .Xauthority files are not used, it may be possible to obtain unauthorized access to the X Windows host.'
  desc 'check', 'Check for .Xauthority files being utilized by looking for such files in the home directory of a user that uses X.

Procedure:
# cd ~someuser
# ls -la .Xauthority

If the .Xauthority file does not exist, ask the SA if the user is using X Windows. If the user is utilizing X Windows and the .Xauthority file does not exist, this is a finding.'
  desc 'fix', 'Ensure the X Windows host is configured to write .Xauthority files into user home directories. Edit the Xaccess file. Ensure the line that writes the .Xauthority file is uncommented.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29123r485213_chk'
  tag severity: 'medium'
  tag gid: 'V-226961'
  tag rid: 'SV-226961r603265_rule'
  tag stig_id: 'GEN005160'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29111r485214_fix'
  tag 'documentable'
  tag legacy: ['V-850', 'SV-850']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
