control 'SV-33175' do
  title 'User specific directories must not be globally enabled.'
  desc 'The UserDir directive must be disabled so that user home directories are not accessed via the web site with a tilde (~) preceding the username. The directive also sets the path name of the directory that will be accessed. The user directories should not be globally enabled since it allows anonymous access to anything users may want to share with other users on the network. Also consider that every time a new account is created on the system, there is potentially new content available via the web site.'
  desc 'check', 'Open a command prompt window.

Navigate to the “bin” directory (in many cases this may be [Drive Letter]:\\[directory path]\\Apache Software Foundation\\Apache2.2\\bin>).

Enter the following command: httpd –M <enter>
NOTE: Some installations may be running under apache.exe. In such case, validate by running the following command: apache -M <enter>

This will provide a list of all loaded modules. If the following module is found this is a finding: userdir_module.'
  desc 'fix', 'Disable the userdir_module by adding a "#" in front of it within the httpd.conf file, and restarting the Apache service.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33810r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26302'
  tag rid: 'SV-33175r2_rule'
  tag stig_id: 'WA00525 W22'
  tag gtitle: 'WA00525'
  tag fix_id: 'F-29460r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
