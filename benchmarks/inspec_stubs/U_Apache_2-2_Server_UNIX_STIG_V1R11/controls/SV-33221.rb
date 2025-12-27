control 'SV-33221' do
  title 'User specific directories must not be globally enabled.'
  desc 'The UserDir directive must be disabled so that user home directories are not accessed via the web site with a tilde (~) preceding the username. The directive also sets the path name of the directory that will be accessed. The user directories should not be globally enabled since it allows anonymous access to anything users may want to share with other users on the network. Also consider that every time a new account is created on the system, there is potentially new content available via the web site.'
  desc 'check', 'Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules. If userdir_module is listed, this is a finding.'
  desc 'fix', 'Edit the httpd.conf file and remove userdir_module.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33764r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26302'
  tag rid: 'SV-33221r1_rule'
  tag stig_id: 'WA00525 A22'
  tag gtitle: 'WA00525'
  tag fix_id: 'F-29401r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
