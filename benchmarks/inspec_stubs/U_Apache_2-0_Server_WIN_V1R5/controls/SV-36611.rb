control 'SV-36611' do
  title 'Web Distributed Authoring and Versioning (WebDAV) must be disabled.'
  desc "The Apache mod_dav and mod_dav_fs modules support WebDAV ('Web-based Distributed Authoring and Versioning') functionality for Apache. WebDAV is an extension to the HTTP protocol which allows clients to create, move, and delete files and resources on the web server. WebDAV is not widely used, and has serious security concerns as it may allow clients to modify unauthorized files on the web server. Therefore, the WebDav modules mod_dav and mod_dav_fs should be disabled."
  desc 'check', 'Open the httpd.conf file.

Search for uncommented LoadModule dav_module, LoadModule dav_fs_module, and LoadModule dav_lock_module directive statements.  If any of these statements are found uncommented, this is a finding.'
  desc 'fix', 'Edit the httpd.conf file and remove, or comment out, the following modules statements:  dav_module, dav_fs_module, and dav_lock_module.  Restart the server.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-35706r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26287'
  tag rid: 'SV-36611r1_rule'
  tag stig_id: 'WA00505 W20'
  tag gtitle: 'WA00505'
  tag fix_id: 'F-30948r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECAN-1'
end
