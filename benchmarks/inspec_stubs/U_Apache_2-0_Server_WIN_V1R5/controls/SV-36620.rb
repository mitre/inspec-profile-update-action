control 'SV-36620' do
  title 'Automatic directory indexing must be disabled.'
  desc 'To identify the type of web servers and versions software installed it is common for attackers to scan for icons or special content specific to the server type and version. A simple request like http://example.com/icons/apache_pb2.png may tell the attacker that the server is Apache 2.2 as shown below. The many icons are used primary for auto indexing, which is recommended to be disabled.'
  desc 'check', 'Open the httpd.conf file. 

Search for an uncommented LoadModule autoindex_module directive statement. If this statement is found uncommented, this is a finding.'
  desc 'fix', 'Disable the autoindex_module by adding a "#" in front of it within the httpd.conf file, and restarting the Apache httpd service.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-35717r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26368'
  tag rid: 'SV-36620r1_rule'
  tag stig_id: 'WA00515 W20'
  tag gtitle: 'WA00515'
  tag fix_id: 'F-30959r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'DCSQ-1, DCSW-1'
end
