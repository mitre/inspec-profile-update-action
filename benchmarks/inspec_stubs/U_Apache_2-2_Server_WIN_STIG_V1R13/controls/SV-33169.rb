control 'SV-33169' do
  title 'Web Distributed Authoring and Versioning (WebDAV) must be disabled.'
  desc "The Apache mod_dav and mod_dav_fs modules support WebDAV ('Web-based Distributed Authoring and Versioning') functionality for Apache. WebDAV is an extension to the HTTP protocol which allows clients to create, move, and delete files and resources on the web server. WebDAV is not widely used, and has serious security concerns as it may allow clients to modify unauthorized files on the web server. Therefore, the WebDav modules mod_dav and mod_dav_fs should be disabled."
  desc 'check', 'Open a command prompt window.

Navigate to the “bin” directory (in many cases this may be [Drive Letter]:\\[directory path]\\Apache Software Foundation\\Apache2.2\\bin>).

Enter the following command: httpd –M <enter>
NOTE: Some installations may be running under apache.exe. In such case, validate by running the following command: apache -M <enter>
This will provide a list of all loaded modules. If any of the following modules are found this is a finding: dav_module, dav_fs_module, or dav_lock_module.'
  desc 'fix', 'Disable all WebDAV modules by adding a "#" in front of them within the httpd.conf file, and restarting the Apache service.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33807r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26287'
  tag rid: 'SV-33169r2_rule'
  tag stig_id: 'WA00505 W22'
  tag gtitle: 'WA00505'
  tag fix_id: 'F-29456r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
