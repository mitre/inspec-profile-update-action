control 'SV-33025' do
  title 'Logs of web server access and errors must be established and maintained'
  desc 'A major tool in exploring the web site use, attempted use, unusual conditions, and problems are reported in the access and error logs. In the event of a security incident, these logs can provide the SA and the web manager with valuable information. Without these log files, SAs and web managers are seriously hindered in their efforts to respond appropriately to suspicious or criminal actions targeted at the web site.'
  desc 'check', 'To view a list of loaded modules enter the following command: 

/usr/local/apache2/bin/httpd -M 

If the following module is not found, this is a finding: "log_config_module"'
  desc 'fix', 'Edit the httpd.conf file and add the following module to configure logging.

"log_config_module"'
  impact 0.5
  ref 'DPMS Target Apache Site 2.x'
  tag check_id: 'C-33707r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2250'
  tag rid: 'SV-33025r1_rule'
  tag stig_id: 'WG240 A22'
  tag gtitle: 'WG240'
  tag fix_id: 'F-29339r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
