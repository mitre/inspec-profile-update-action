control 'SV-36612' do
  title 'Web server status module will be disabled.'
  desc 'The Apache mod_info module provides information on the server configuration via access to a /server-info URL location, while the mod_status module provides current server performance statistics. While having server configuration and status information available as a web page may be convenient, it’s recommended that these modules NOT be enabled: Once mod_info is loaded into the server, its handler capability is available in per-directory .htaccess files and can leak sensitive information from the configuration directives of other Apache modules such as system paths, usernames/passwords, database names, etc. If mod_status is loaded into the server, its handler capability is available in all configuration files, including per-directory files (e.g., .htaccess) and may have security-related ramifications.'
  desc 'check', 'Open the httpd.conf file. 

Search for uncommented LoadModule info_module and LoadModule status_module directive statements. 

If any of these statements are found uncommented, this is a finding.'
  desc 'fix', 'Disable info and status modules by adding a "#" in front of them within the httpd.conf file, and restarting the Apache httpd service.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-35707r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26294'
  tag rid: 'SV-36612r1_rule'
  tag stig_id: 'WA00510 W20'
  tag gtitle: 'WA00510'
  tag fix_id: 'F-30949r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'ECAN-1'
end
