control 'SV-36668' do
  title 'Logs of web server access and errors must be established and maintained.'
  desc 'A major tool in exploring the web site use, attempted use, unusual conditions, and problems are reported in the access and error logs. In the event of a security incident, these logs can provide the SA and the web manager with valuable information. Without these log files, SAs and web managers are seriously hindered in their efforts to respond appropriately to suspicious or criminal actions targeted at the web site.'
  desc 'check', 'Open the httpd.conf file. 

Search for a commented LoadModule log_config_module directive statement. 

If this statement is found commented, this is a finding.'
  desc 'fix', 'Uncomment the LoadModule log_config_module statement and restart the Apache service.'
  impact 0.5
  ref 'DPMS Target Apache Site 2.0'
  tag check_id: 'C-35750r1_chk'
  tag severity: 'medium'
  tag gid: 'V-2250'
  tag rid: 'SV-36668r1_rule'
  tag stig_id: 'WG240 W20'
  tag gtitle: 'WG240'
  tag fix_id: 'F-30993r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECAT-1, ECAT-2'
end
