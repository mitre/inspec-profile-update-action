control 'SV-33171' do
  title 'Web server status module must be disabled.'
  desc 'The Apache mod_info module provides information on the server configuration via access to a /server-info URL location, while the mod_status module provides current server performance statistics. While having server configuration and status information available as a web page may be convenient, it is recommended that these modules not be enabled: Once mod_info is loaded into the server, its handler capability is available in per-directory .htaccess files and can leak sensitive information from the configuration directives of other Apache modules such as system paths, usernames/passwords, database names, etc. If mod_status is loaded into the server, its handler capability is available in all configuration files, including per-directory files (e.g., .htaccess) and may have security-related ramifications.'
  desc 'check', 'Open a command prompt window.

Navigate to the “bin” directory (in many cases this may be [Drive Letter]:\\[directory path]\\Apache Software Foundation\\Apache2.2\\bin>).

Enter the following command: httpd –M <enter>
NOTE: Some installations may be running under apache.exe. In such case, validate by running the following command: apache -M <enter>

This will provide a list of all loaded modules. If any of the following modules are found this is a finding: info_module & status_module.'
  desc 'fix', 'Disable info and status modules by adding a "#" in front of them within the httpd.conf file, and restarting the Apache service.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33808r3_chk'
  tag severity: 'medium'
  tag gid: 'V-26294'
  tag rid: 'SV-33171r2_rule'
  tag stig_id: 'WA00510 W22'
  tag gtitle: 'WA00510'
  tag fix_id: 'F-29457r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
