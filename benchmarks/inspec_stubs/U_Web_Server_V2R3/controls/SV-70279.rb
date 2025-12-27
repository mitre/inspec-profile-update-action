control 'SV-70279' do
  title 'Cookies exchanged between the web server and client, such as session cookies, must have security settings that disallow cookie access outside the originating web server and hosted application.'
  desc 'Cookies are used to exchange data between the web server and the client. Cookies, such as a session cookie, may contain session information and user credentials used to maintain a persistent connection between the user and the hosted application since HTTP/HTTPS is a stateless protocol. 

When the cookie parameters are not set properly (i.e., domain and path parameters), cookies can be shared within hosted applications residing on the same web server or to applications hosted on different web servers residing on the same domain.'
  desc 'check', 'Review the web server documentation and configuration to determine if cookies between the web server and client are accessible by applications or web servers other than the originating pair.

If the cookie information is accessible outside the originating pair, this is a finding.'
  desc 'fix', 'Configure the web server to set properties within cookies to disallow the cookie to be accessed by other web servers and applications.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-56595r2_chk'
  tag severity: 'medium'
  tag gid: 'V-56025'
  tag rid: 'SV-70279r2_rule'
  tag stig_id: 'SRG-APP-000223-WSR-000011'
  tag gtitle: 'SRG-APP-000223-WSR-000011'
  tag fix_id: 'F-60903r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001664']
  tag nist: ['SC-23 (3)']
end
