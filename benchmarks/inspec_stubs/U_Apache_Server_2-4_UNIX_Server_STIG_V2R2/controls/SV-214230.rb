control 'SV-214230' do
  title 'The Apache web server must use cryptography to protect the integrity of remote sessions.'
  desc 'Data exchanged between the user and the Apache web server can range from static display data to credentials used to log on to the hosted application. Even when data appears to be static, the non-displayed logic in a web page may expose business logic or trusted system relationships. The integrity of all the data being exchanged between the user and the Apache web server must always be trusted. To protect the integrity and trust, encryption methods should be used to protect the complete communication session.

'
  desc 'check', %q(In a command line, run "httpd -M | grep -i ssl_module".

If the "ssl_module" is not found, this is a finding. 

Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# httpd -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Search for the "SSLCACertificateFile" directive:

# cat /<path_to_file>/httpd.conf | grep -i "SSLCACertificateFile"

Review the path of the "SSLCACertificateFile" directive.

Review the contents of <'path of SSLCACertificateFile'>\ca-bundle.crt.

Examine the contents of this file to determine if the trusted CAs are DoD approved.

If the trusted CA that is used to authenticate users to the website does not lead to an approved DoD CA, this is a finding.

NOTE: There are non-DoD roots that must be on the server for it to function. Some applications, such as antivirus programs, require root CAs to function. DoD-approved certificate can include the External Certificate Authorities (ECA) if approved by the AO. The PKE InstallRoot 3.06 System Administrator Guide (SAG), dated 08 Jul 2008, contains a complete list of DoD, ECA, and IECA CAs.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# httpd -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Ensure the "SSLProtocol" is added and looks like the following:

SSLProtocol -ALL +TLSv1.2

Restart Apache: apachectl restart)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15444r276950_chk'
  tag severity: 'medium'
  tag gid: 'V-214230'
  tag rid: 'SV-214230r612240_rule'
  tag stig_id: 'AS24-U1-000030'
  tag gtitle: 'SRG-APP-000014-WSR-000006'
  tag fix_id: 'F-15442r276951_fix'
  tag satisfies: ['SRG-APP-000014-WSR-000006', 'SRG-APP-000015-WSR-000014', 'SRG-APP-000033-WSR-000169', 'SRG-APP-000172-WSR-000104', 'SRG-APP-000179-WSR-000110', 'SRG-APP-000179-WSR-000111', 'SRG-APP-000224-WSR-000139', 'SRG-APP-000427-WSR-000186', 'SRG-APP-000439-WSR-000151', 'SRG-APP-000439-WSR-000152', 'SRG-APP-000439-WSR-000153', 'SRG-APP-000442-WSR-000182']
  tag 'documentable'
  tag legacy: ['SV-102689', 'V-92601']
  tag cci: ['CCI-000068', 'CCI-000197', 'CCI-000213', 'CCI-000803', 'CCI-001188', 'CCI-001453', 'CCI-002418', 'CCI-002422', 'CCI-002470']
  tag nist: ['AC-17 (2)', 'IA-5 (1) (c)', 'AC-3', 'IA-7', 'SC-23 (3)', 'AC-17 (2)', 'SC-8', 'SC-8 (2)', 'SC-23 (5)']
end
