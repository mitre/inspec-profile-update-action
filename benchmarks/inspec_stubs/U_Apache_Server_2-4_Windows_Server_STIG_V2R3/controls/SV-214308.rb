control 'SV-214308' do
  title 'The Apache web server must use encryption strength in accordance with the categorization of data hosted by the Apache web server when remote connections are provided.'
  desc 'The Apache web server has several remote communications channels. Examples are user requests via http/https, communication to a backend database, and communication to authenticate users. The encryption used to communicate must match the data that is being retrieved or presented.

Methods of communication are "http" for publicly displayed information, "https" to encrypt when user data is being transmitted, VPN tunneling, or other encryption methods to a database.

'
  desc 'check', %q(In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -M" to view a list of installed modules.

If the "ssl_module" is not enabled, this is a finding.

Review the <'INSTALL PATH'>\conf\httpd.conf file to determine if the "SSLProtocol" directive exists and looks like the following:

SSLProtocol -ALL +TLSv1.2 -SSLv2 -SSLv3

If the directive does not exist or exists but does not contain "ALL +TLSv1.2 -SSLv2 -SSLv3", this is a finding.)
  desc 'fix', %q(Ensure the "ssl_module" is loaded in the httpd.conf file (not commented out).

Ensure the "SSLProtocol" is added and looks like the following in the <'INSTALL PATH'>\conf\httpd.conf file:

SSLProtocol -ALL +TLSv1.2

Restart the Apache service.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15520r505089_chk'
  tag severity: 'medium'
  tag gid: 'V-214308'
  tag rid: 'SV-214308r879519_rule'
  tag stig_id: 'AS24-W1-000030'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-15518r505090_fix'
  tag satisfies: ['SRG-APP-000014-WSR-000006', 'SRG-APP-000015-WSR-000014', 'SRG-APP-000033-WSR-000169', 'SRG-APP-000179-WSR-000110', 'SRG-APP-000179-WSR-000111', 'SRG-APP-000439-WSR-000152', 'SRG-APP-000439-WSR-000154', 'SRG-APP-000439-WSR-000188', 'SRG-APP-000442-WSR-000182']
  tag 'documentable'
  tag legacy: ['SV-102419', 'V-92331']
  tag cci: ['CCI-000068', 'CCI-000213', 'CCI-000803', 'CCI-001453', 'CCI-002418', 'CCI-002422']
  tag nist: ['AC-17 (2)', 'AC-3', 'IA-7', 'AC-17 (2)', 'SC-8', 'SC-8 (2)']
end
