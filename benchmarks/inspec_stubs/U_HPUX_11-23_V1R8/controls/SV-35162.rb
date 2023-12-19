control 'SV-35162' do
  title 'All .Xauthority files must have mode 0600 or less permissive.'
  desc '.Xauthority files ensure the user is authorized to access the specific X Windows host. Excessive permissions may permit unauthorized modification of these files, which could lead to Denial of Service to authorized access or allow unauthorized access to be obtained.'
  desc 'check', 'Get a list of (non-system account) users and the associated home directories.
# cat /etc/passwd | cut -f 1,6 -d  ":"	

Check the file permissions for the user .Xauthority files.
# ls -lLa .Xauthority

If the file mode is more permissive than 0600, this is finding.'
  desc 'fix', 'Change the mode of the .Xauthority files.
# chmod 0600 .Xauthority'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36599r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12014'
  tag rid: 'SV-35162r1_rule'
  tag stig_id: 'GEN005180'
  tag gtitle: 'GEN005180'
  tag fix_id: 'F-31965r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-000225']
  tag nist: ['AC-6']
end
