control 'SV-102601' do
  title 'The Apache web server must be configured to use a specified IP address and port.'
  desc 'The web server must be configured to listen on a specified IP address and port. Without specifying an IP address and port for the web server to use, the web server will listen on all IP addresses available to the hosting server. If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address.

Accessing the hosted application through an IP address normally used for non-application functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.'
  desc 'check', %q(Review the <'INSTALLED PATH'>\conf\httpd.conf file and search for the following directive:

Listen

For any enabled "Listen" directives, verify they specify both an IP address and port number.

If the "Listen" directive is found with only an IP address or only a port number specified, this is finding.
 
If the IP address is all zeros (i.e. 0.0.0.0:80 or [::ffff:0.0.0.0]:80), this is a finding.

If the "Listen" directive does not exist, this is a finding.)
  desc 'fix', %q(Edit the <'INSTALLED PATH'>\conf\httpd.conf file and set the "Listen" directive to listen on a specific IP address and port.)
  impact 0.5
  ref 'DPMS Target Apache Site 2.4 - Windows'
  tag check_id: 'C-91815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92513'
  tag rid: 'SV-102601r1_rule'
  tag stig_id: 'AS24-W2-000360'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag fix_id: 'F-98755r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
