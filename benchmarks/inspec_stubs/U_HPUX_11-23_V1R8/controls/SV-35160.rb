control 'SV-35160' do
  title 'Any X Windows host must write .Xauthority files.'
  desc '.Xauthority files ensure the user is authorized to access the specific X Windows host. If .Xauthority files are not used, it may be possible to obtain unauthorized access to the X Windows host.'
  desc 'check', 'Check for .Xauthority files being utilized by looking for such files in the home directory of a user using X. Get a list of (non-system account) users and the associated home directories.
# cat /etc/passwd | cut -f 1,6 -d ":"       

Inspect individual user home directories for the .Xauthority file.
# find <f6 from the above command> -type f -name "\\.Xauthority" -exec ls -lLa {} \\;

If the .Xauthority file does not exist, ask the SA if the user is using X Windows. If the user is utilizing X Windows and the .Xauthority file does not exist, this is a finding.'
  desc 'fix', 'Ensure the X Windows host is configured to write .Xauthority files into user home directories. Edit the file. Ensure the line writing the .Xauthority file is uncommented.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36598r1_chk'
  tag severity: 'medium'
  tag gid: 'V-850'
  tag rid: 'SV-35160r1_rule'
  tag stig_id: 'GEN005160'
  tag gtitle: 'GEN005160'
  tag fix_id: 'F-31964r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECCD-2, ECCD-1'
  tag cci: ['CCI-000297']
  tag nist: ['CM-2 b 2']
end
