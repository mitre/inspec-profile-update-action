control 'SV-214258' do
  title 'The Apache web server must set an inactive timeout for sessions.'
  desc 'Leaving sessions open indefinitely is a major security risk. An attacker can easily use an already authenticated session to access the hosted application as the previously authenticated user. By closing sessions after a set period of inactivity, the Apache web server can make certain that those sessions that are not closed through the user logging out of an application are eventually closed. mod_reqtimeout is an Apache module designed to shut down connections from clients taking too long to send their request, as seen in many attacks. This module provides a directive that allows Apache to close the connection if it senses that the client is not sending data quickly enough.

Acceptable values are 5 minutes for high-value applications, 10 minutes for medium-value applications, and 20 minutes for low-value applications.'
  desc 'check', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Note: The apachectl front end is the preferred method for locating the Apache httpd file. For some Linux distributions, "apache2ctl -V" or  "httpd -V" can also be used. 

Verify the "reqtimeout_module" is loaded:

Change to the root directory of Apache and run the following command to verify the "reqtimeout_module" is loaded:

# httpd -M | grep reqtimeout_module
Outout: reqtimeout_module (shared)

If the "reqtimeout_module" is not loaded, this is a finding.

Verify the "RequestReadTimeout" directive is configured. 
Example: RequestReadTimeout handshake=5 header=10 body=30
Allows for 5 seconds to complete the TLS handshake, 10 seconds to receive the request headers, and 30 seconds for receiving the request body.
The values will depend upon the website. 
The intent of this requirement is to ensure the RequestReadTimeout is explicitly configured.
If the "reqtimeout_module" is loaded and the "RequestReadTimeout" directive is not configured, this is a finding.)
  desc 'fix', %q(Determine the location of the "HTTPD_ROOT" directory and the "httpd.conf" file:

# apachectl -V | egrep -i 'httpd_root|server_config_file'
-D HTTPD_ROOT="/etc/httpd"
-D SERVER_CONFIG_FILE="conf/httpd.conf"

Load the "reqtimeout_module".

Set the "RequestReadTimeout" directive to specific values applicable to the website.)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15472r881448_chk'
  tag severity: 'medium'
  tag gid: 'V-214258'
  tag rid: 'SV-214258r881450_rule'
  tag stig_id: 'AS24-U1-000650'
  tag gtitle: 'SRG-APP-000295-WSR-000134'
  tag fix_id: 'F-15470r881449_fix'
  tag 'documentable'
  tag legacy: ['SV-102793', 'V-92705']
  tag cci: ['CCI-002361']
  tag nist: ['AC-12']
end
