control 'SV-99761' do
  title 'tc Server CaSa must remove all export ciphers to protect the confidentiality and integrity of transmitted information.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference.  The web server will reply with the cipher suite it will use for communication from the client list.  If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.

An essential configuration file for tc Server is “catalina.properties”. Properly configured, tc Server will not provide the weaker, export ciphers.'
  desc 'check', "At the command prompt, execute the following command:

grep -A 10 vmware-casa.ssl.ciphers.list /usr/lib/vmware-casa/casa-webapp/conf/catalina.properties

If any export ciphers are listed, this is a finding.

Note: To view a list of export ciphers, at the command prompt execute the following command:

openssl ciphers 'EXP'"
  desc 'fix', "Navigate to and open /usr/lib/vmware-casa/casa-webapp/conf/catalina.properties.

Navigate to the “vmware-casa.ssl.ciphers.list” setting.

Remove any export ciphers from “vmware-casa.ssl.ciphers.list”.

Note: To view a list of export ciphers, at the command prompt execute the following command:

openssl ciphers 'EXP'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88803r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89111'
  tag rid: 'SV-99761r1_rule'
  tag stig_id: 'VROM-TC-000990'
  tag gtitle: 'SRG-APP-000439-WSR-000188'
  tag fix_id: 'F-95853r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
