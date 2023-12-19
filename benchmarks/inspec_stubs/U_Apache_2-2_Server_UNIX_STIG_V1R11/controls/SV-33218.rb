control 'SV-33218' do
  title 'Web server status module must be disabled.'
  desc 'The Apache mod_info module provides information on the server configuration via access to a /server-info URL location, while the mod_status module provides current server performance statistics. While having server configuration and status information available as a web page may be convenient, it is recommended that these modules not be enabled: Once mod_info is loaded into the server, its handler capability is available in per-directory .htaccess files and can leak sensitive information from the configuration directives of other Apache modules such as system paths, usernames/passwords, database names, etc. If mod_status is loaded into the server, its handler capability is available in all configuration files, including per-directory files (e.g., .htaccess) and may have security-related ramifications.'
  desc 'check', 'Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules.  If any of the following modules are found, this is a finding.

info_module
status_module'
  desc 'fix', 'Edit the httpd.conf file and disable info_module and status_module.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33759r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26294'
  tag rid: 'SV-33218r1_rule'
  tag stig_id: 'WA00510 A22'
  tag gtitle: 'WA00510'
  tag fix_id: 'F-29395r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
