control 'SV-100835' do
  title 'tc Server VCAC must remove all export ciphers to protect the confidentiality and integrity of transmitted information.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference. The web server will reply with the cipher suite it will use for communication from the client list. If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.

An essential configuration file for tc Server is catalina.properties. Properly configured, tc Server will not provide the weaker, export ciphers.'
  desc 'check', 'At the command prompt, execute the following command:

grep ciphers /etc/vcac/catalina.properties

If any export ciphers are listed, this is a finding.'
  desc 'fix', %q(Navigate to and open /etc/vcac/catalina.properties.

Navigate to the "cipher" setting.

Remove any export ciphers from "cipher".

Note: To view a list of export ciphers, at the command prompt execute the following command:

openssl ciphers 'EXP')
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89877r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90185'
  tag rid: 'SV-100835r1_rule'
  tag stig_id: 'VRAU-TC-000930'
  tag gtitle: 'SRG-APP-000439-WSR-000188'
  tag fix_id: 'F-96927r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
