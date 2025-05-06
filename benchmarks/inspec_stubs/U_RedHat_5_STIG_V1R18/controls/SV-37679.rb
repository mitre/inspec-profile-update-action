control 'SV-37679' do
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
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36866r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12014'
  tag rid: 'SV-37679r1_rule'
  tag stig_id: 'GEN005180'
  tag gtitle: 'GEN005180'
  tag fix_id: 'F-31822r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
