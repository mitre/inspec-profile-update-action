control 'SV-33219' do
  title 'Automatic directory indexing must be disabled.'
  desc 'To identify the type of web servers and versions software installed it is common for attackers to scan for icons or special content specific to the server type and version. A simple request like http://example.com/icons/apache_pb2.png may tell the attacker that the server is Apache 2.2 as shown below. The many icons are used primary for auto indexing, which is recommended to be disabled.'
  desc 'check', 'Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules. If autoindex_module is found, this is a finding.'
  desc 'fix', 'Edit the httpd.conf file and remove autoindex_module.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-33828r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26368'
  tag rid: 'SV-33219r1_rule'
  tag stig_id: 'WA00515 A22'
  tag gtitle: 'WA00515'
  tag fix_id: 'F-29492r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
