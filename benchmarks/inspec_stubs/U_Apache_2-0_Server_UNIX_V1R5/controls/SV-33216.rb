control 'SV-33216' do
  title 'Web Distributed Authoring and Versioning (WebDAV) must be disabled.'
  desc "The Apache mod_dav and mod_dav_fs modules support WebDAV ('Web-based Distributed Authoring and Versioning') functionality for Apache. WebDAV is an extension to the HTTP protocol which allows clients to create, move, and delete files and resources on the web server. WebDAV is not widely used, and has serious security concerns as it may allow clients to modify unauthorized files on the web server. Therefore, the WebDav modules mod_dav and mod_dav_fs should be disabled."
  desc 'check', 'Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules.  If any of the following modules are found, this is a finding. 

dav_module
dav_fs_module
dav_lock_module'
  desc 'fix', 'Edit the httpd.conf file and remove the following modules:

dav_module
dav_fs_module
dav_lock_module'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33754r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26287'
  tag rid: 'SV-33216r1_rule'
  tag stig_id: 'WA00505 A22'
  tag gtitle: 'WA00505'
  tag fix_id: 'F-29390r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECAN-1'
end
