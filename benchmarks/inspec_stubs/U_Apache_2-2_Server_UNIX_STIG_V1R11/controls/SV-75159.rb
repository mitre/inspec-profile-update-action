control 'SV-75159' do
  title 'The web server must remove all export ciphers from the cipher suite.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference.  The web server will reply with the cipher suite it will use for communication from the client list.  If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
  desc 'check', 'Locate the Apache httpd.conf and ssl.conf file if available.
Open the httpd.conf and ssl.conf file with an editor and search for the following uncommented directive: SSLCipherSuite
For all enabled SSLCipherSuite directives, ensure the cipher specification string contains the kill cipher from list option for all export cipher suites, i.e., !EXPORT, which may be abbreviated !EXP.  If the SSLCipherSuite directive does not contain !EXPORT or there are no enabled SSLCipherSuite directives, this is a finding.'
  desc 'fix', 'Update the cipher specification string for all enabled SSLCipherSuite directives to include !EXPORT.'
  impact 0.5
  ref 'DPMS Target Apache Instance 2.x'
  tag check_id: 'C-61651r2_chk'
  tag severity: 'medium'
  tag gid: 'V-60707'
  tag rid: 'SV-75159r1_rule'
  tag stig_id: 'WG345 A22'
  tag gtitle: 'WG345'
  tag fix_id: 'F-66387r2_fix'
  tag 'documentable'
  tag responsibility: 'Web Administrator'
end
