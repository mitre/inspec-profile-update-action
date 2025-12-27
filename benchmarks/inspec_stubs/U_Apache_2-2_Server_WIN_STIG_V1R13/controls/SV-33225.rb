control 'SV-33225' do
  title 'Automatic directory indexing must be disabled.'
  desc 'To identify the type of web servers and versions software installed it is common for attackers to scan for icons or special content specific to the server type and version. A simple request like http://example.com/icons/apache_pb2.png may tell the attacker that the server is Apache 2.2 as shown below. The many icons are used primary for auto indexing, which is recommended to be disabled.'
  desc 'check', 'Open a command prompt window.

Navigate to the “bin” directory (in many cases this may be [Drive Letter]:\\[directory path]\\Apache Software Foundation\\Apache2.2\\bin>).

Enter the following command and press Enter: httpd –M

This will provide a list of all loaded modules. If the following module is found this is a finding: autoindex_module.'
  desc 'fix', 'Disable the autoindex_module by adding a "#" in front of it within the httpd.conf file, and restarting the Apache httpd service.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33829r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26368'
  tag rid: 'SV-33225r1_rule'
  tag stig_id: 'WA00515 W22'
  tag gtitle: 'WA00515'
  tag fix_id: 'F-29494r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
