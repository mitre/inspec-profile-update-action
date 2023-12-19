control 'SV-33228' do
  title 'The web server must be configured to listen on a specific IP address and port.'
  desc 'The Apache Listen directive specifies the IP addresses and port numbers the Apache web server will listen for requests. Rather than be unrestricted to listen on all IP addresses available to the system, the specific IP address or addresses intended must be explicitly specified. Specifically a Listen directive with no IP address specified, or with an IP address of zero’s should not be used. Having multiple interfaces on web servers is fairly common, and without explicit Listen directives, the web server is likely to be listening on an inappropriate IP address / interface that were not intended for the web server. Single homed system with a single IP addressed are also required to have an explicit IP address in the Listen directive, in case additional interfaces are added to the system at a later date.'
  desc 'check', 'Enter the following command:

grep "Listen" /usr/local/apache2/conf/httpd.conf

Review the results for the following  directive:   Listen 

For any enabled Listen directives ensure they specify both an IP address and port number.

If the Listen directive is found with only an IP address, or only a port number specified, this is finding.  
If the IP address is all zeros (i.e. 0.0.0.0:80 or [::ffff:0.0.0.0]:80, this is a finding.  
If the Listen directive does not exist, this is a finding.'
  desc 'fix', 'Edit the httpd.conf file and set the "Listen directive" to listen on a specific IP address and port.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.0'
  tag check_id: 'C-33782r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26326'
  tag rid: 'SV-33228r1_rule'
  tag stig_id: 'WA00555 A22'
  tag gtitle: 'WA00555'
  tag fix_id: 'F-29425r1_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
  tag ia_controls: 'DCFA-1, DCPP-1'
end
