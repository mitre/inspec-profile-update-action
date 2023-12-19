control 'SV-75835' do
  title 'The web server must remove all export ciphers to protect the confidentiality and integrity of transmitted information.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference.  The web server will reply with the cipher suite it will use for communication from the client list.  If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
  desc 'check', 'Review the web server documentation and deployed configuration to determine if export ciphers are removed.

If the web server does not have the export ciphers removed, this is a finding.'
  desc 'fix', 'Configure the web server to have export ciphers removed.'
  impact 0.5
  ref 'DPMS Target SRG-APP-WSR'
  tag check_id: 'C-62283r1_chk'
  tag severity: 'medium'
  tag gid: 'V-61353'
  tag rid: 'SV-75835r1_rule'
  tag stig_id: 'SRG-APP-000439-WSR-000188'
  tag gtitle: 'SRG-APP-000439-WSR-000188'
  tag fix_id: 'F-67255r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
