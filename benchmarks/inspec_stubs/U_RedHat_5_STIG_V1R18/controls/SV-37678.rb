control 'SV-37678' do
  title 'Any X Windows host must write .Xauthority files.'
  desc '.Xauthority files ensure the user is authorized to access specific X Windows host. If .Xauthority files are not used, it may be possible to obtain unauthorized access to the X Windows host.'
  desc 'check', "Check for .Xauthority or .xauth files being utilized by looking for such files in the home directory of a user.

Procedure:

# find / -name '.xauth*' | more

If no .xauth files are found in a user's home directory, ensure that Xwindows is not active on the system by performing the command:

# ps -ef | grep X

If Xwindows is not running, this rule is not applicable.

If the .Xauthority or .xauth (followed by apparently random characters) files do not exist, ask the SA if the user is using Xwindows.

If the user is utilizing Xwindows and none of these files exist, this is a finding."
  desc 'fix', 'Ensure the X Windows host is configured to write .Xauthority files into user home directories. Edit the Xaccess file. Ensure the line writing the .Xauthority file is uncommented.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36865r5_chk'
  tag severity: 'medium'
  tag gid: 'V-850'
  tag rid: 'SV-37678r3_rule'
  tag stig_id: 'GEN005160'
  tag gtitle: 'GEN005160'
  tag fix_id: 'F-31811r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000297']
  tag nist: ['CM-2 b 2']
end
