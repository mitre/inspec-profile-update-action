control 'SV-214396' do
  title 'An Apache web server must maintain the confidentiality of controlled information during transmission through the use of an approved TLS version.'
  desc 'Transport Layer Security (TLS) is a required transmission protocol for a web server hosting controlled information. The use of TLS provides confidentiality of data in transit between the web server and client. FIPS 140-2 approved TLS versions must be enabled and non-FIPS-approved SSL versions must be disabled.

NIST SP 800-52 defines the approved TLS versions for government applications.

'
  desc 'check', %q(In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -M" to view a list of installed modules.

If the module "mod_ssl" is not enabled, this is a finding.

Review the <'INSTALLED PATH'>\conf\httpd.conf file to determine if the "SSLProtocol" directive exists and looks like the following:

SSLProtocol -ALL +TLSv1.2

If the directive does not exist and does not contain "-ALL +TLSv1.2", this is a finding.)
  desc 'fix', %q(Ensure the "SSLProtocol" is added and looks like the following in the <'INSTALLED PATH'>\conf\httpd.conf file:

SSLProtocol -ALL +TLSv1.2

Ensure the "SSLEngine" parameter is set to "ON" inside the "VirtualHost" directive.)
  impact 0.7
  ref 'DPMS Target Apache Server 2.4 Windows Site'
  tag check_id: 'C-15607r277929_chk'
  tag severity: 'high'
  tag gid: 'V-214396'
  tag rid: 'SV-214396r395466_rule'
  tag stig_id: 'AS24-W2-000890'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-15605r277930_fix'
  tag satisfies: ['SRG-APP-000014-WSR-000006', 'SRG-APP-000015-WSR-000014', 'SRG-APP-000033-WSR-000169', 'SRG-APP-000172-WSR-000104', 'SRG-APP-000179-WSR-000110', 'SRG-APP-000179-WSR-000111', 'SRG-APP-000206-WSR-000128', 'SRG-APP-000439-WSR-000151', 'SRG-APP-000439-WSR-000152', 'SRG-APP-000439-WSR-000156', 'SRG-APP-000441-WSR-000181', 'SRG-APP-000442-WSR-000182', 'SRG-APP-000429-WSR-000113']
  tag 'documentable'
  tag legacy: ['SV-102677', 'V-92589']
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-000213', 'CCI-000803', 'CCI-001166', 'CCI-001453', 'CCI-002418', 'CCI-002420', 'CCI-002422', 'CCI-002476']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'AC-3', 'IA-7', 'SC-18 (1)', 'AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-8 (2)', 'SC-28 (1)']
end
