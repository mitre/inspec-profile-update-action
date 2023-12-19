control 'SV-36614' do
  title 'User specific directories must not be globally enabled.'
  desc 'The UserDir directive must be disabled so that user home directories are not accessed via the web site with a tilde (~) preceding the username. The directive also sets the path name of the directory that will be accessed. The user directories should not be globally enabled since it allows anonymous access to anything users may want to share with other users on the network. Also consider that every time a new account is created on the system, there is potentially new content available via the web site.'
  desc 'check', 'Open the httpd.conf file. 

Search for an uncommented LoadModule userdir_module directive statement.

If this statement is found uncommented, this is a finding.'
  desc 'fix', 'Disable the userdir_module by adding a "#" in front of it within the httpd.conf file, and restarting the Apache httpd service.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-35709r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26302'
  tag rid: 'SV-36614r1_rule'
  tag stig_id: 'WA00525 W20'
  tag gtitle: 'WA00525'
  tag fix_id: 'F-30951r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'IAAC-1'
end
