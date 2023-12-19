control 'SV-241737' do
  title 'tc Server UI must remove all export ciphers to protect the confidentiality and integrity of transmitted information.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference.  The web server will reply with the cipher suite it will use for communication from the client list.  If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.

An essential configuration file for tc Server is “catalina.properties”. Properly configured, tc Server will not provide the weaker, export ciphers.'
  desc 'check', "At the command prompt, execute the following command:

grep vmware-ssl.ssl.ciphers.list /usr/lib/vmware-vcops/tomcat-web-app/conf/catalina.properties

If any export ciphers are listed, this is a finding.

Note: To view a list of export ciphers, at the command prompt execute the following command:

openssl ciphers 'EXP'"
  desc 'fix', "Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/catalina.properties.

Navigate to the “vmware-ssl.ssl.ciphers.list” setting.

Remove any export ciphers from “vmware-ssl.ssl.ciphers.list”.

Note: To view a list of export ciphers, at the command prompt execute the following command:

openssl ciphers 'EXP'"
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-45013r854964_chk'
  tag severity: 'medium'
  tag gid: 'V-241737'
  tag rid: 'SV-241737r879810_rule'
  tag stig_id: 'VROM-TC-000985'
  tag gtitle: 'SRG-APP-000439-WSR-000188'
  tag fix_id: 'F-44972r684072_fix'
  tag 'documentable'
  tag legacy: ['SV-99759', 'V-89109']
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
