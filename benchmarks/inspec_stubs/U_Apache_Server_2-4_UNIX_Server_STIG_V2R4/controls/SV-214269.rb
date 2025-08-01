control 'SV-214269' do
  title 'The Apache web server must remove all export ciphers to protect the confidentiality and integrity of transmitted information.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the Apache web server, the client sends a list of supported cipher suites in order of preference. The Apache web server will reply with the cipher suite it will use for communication from the client list. If an attacker can intercept the submission of cipher suites to the Apache web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.

Configuring the Apache server with only strong ciphersuites, denying or disabling weak ciphersuites, will prevent this vulnerability.'
  desc 'check', 'Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" and "ssl.conf" files:

Search the httpd.conf and ssl.conf file for the following uncommented directive: SSLCipherSuite

# cat httpd.conf  | grep -i SSLCipherSuite
Output: None

# cat /etc/httpd/conf.d/ssl.conf | grep -i SSLCipherSuite
Output: SSLCipherSuite HIGH:3DES:!NULL:!MD5:!SEED:!IDEA:!EXPORT

For all enabled SSLCipherSuite directives, ensure the cipher specification string contains the kill cipher from list option for all export cipher suites, i.e., !EXPORT, which may be abbreviated !EXP as in the following example:

Example: SSLCipherSuite="HIGH:MEDIUM:!MD5!EXP:!NULL:!LOW:!ADH

If the SSLCipherSuite directive does not contain !EXPORT or !EXP or there are no enabled SSLCipherSuite directives, this is a finding.'
  desc 'fix', 'Update the cipher specification string for all enabled SSLCipherSuite directives to include !EXPORT.'
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15483r881462_chk'
  tag severity: 'medium'
  tag gid: 'V-214269'
  tag rid: 'SV-214269r881463_rule'
  tag stig_id: 'AS24-U1-000900'
  tag gtitle: 'SRG-APP-000439-WSR-000188'
  tag fix_id: 'F-15481r505086_fix'
  tag 'documentable'
  tag legacy: ['V-92745', 'SV-102833']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
