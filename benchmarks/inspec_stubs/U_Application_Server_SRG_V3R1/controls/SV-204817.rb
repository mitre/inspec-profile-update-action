control 'SV-204817' do
  title 'The application server must remove all export ciphers to protect the confidentiality and integrity of transmitted information.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the application server, the client sends a list of supported cipher suites in order of preference.  The application server will reply with the cipher suite it will use for communication from the client list.  If an attacker can intercept the submission of cipher suites to the application server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
  desc 'check', 'Review the application server documentation and deployed configuration to determine if export ciphers are removed.

If the application server does not have the export ciphers removed, this is a finding.'
  desc 'fix', 'Configure the application server to have export ciphers removed.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4937r283092_chk'
  tag severity: 'medium'
  tag gid: 'V-204817'
  tag rid: 'SV-204817r508029_rule'
  tag stig_id: 'SRG-APP-000439-AS-000274'
  tag gtitle: 'SRG-APP-000439'
  tag fix_id: 'F-4937r283093_fix'
  tag 'documentable'
  tag legacy: ['V-61351', 'SV-75833']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
