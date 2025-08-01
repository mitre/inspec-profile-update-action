control 'SV-256963' do
  title 'The Automation Controller NGINX web server must employ cryptographic mechanisms (TLS/DTLS/SSL) to prevent the unauthorized disclosure of information during transmission.'
  desc 'Preventing the disclosure of transmitted information requires that the Automation Controller web server take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS).

Transmission of data can take place between the web server and a large number of devices/applications external to the web server. Examples are a web client used by a user, a backend database, an audit server, or other web servers in a web cluster.

If data is transmitted unencrypted, the data then becomes vulnerable to disclosure. The disclosure may reveal user identifier/password combinations, website code revealing business logic, or other user personal information.

'
  desc 'check', %q(As a System Administrator for each Automation Controller NGINX web server host, enumerate all available server connections:

NGINXCONF=`nginx -V 2>&1 | tr ' ' '\n' | sed -ne '/conf-path/{s/.*conf-path=\(.*\\)/\1/;p}' ` ; grep '\s*listen'
NGINXCONF | grep -v ssl

Ensure each available server connection that does not use SSL upgrades this connection to use SSL via an allowed method:

- is redirected to an SSL server connection, e.g., "return 301 https://$host:443$request_uri";
- is rewritten to an SSL server URL, e.g., "rewrite ^ https://$host$request_uri? permanent;";
- is dropped silently;
- or used other organizationally approved connection handling.

Examine the NGINX configuration, for example:

vi $NGINXCONF

If any available server connection is not handled or upgraded to SSL via an organizationally approved method, this is a finding.)
  desc 'fix', 'As a System Administrator for each Automation Controller NGINX web server host, for each available server connection that is not handled or upgraded to SSL via an organizationally approved method, perform one of the following actions:

Remove the available server connections.
OR
Upgrade the connection via redirect to an SSL server connection.
OR
Rewrite the connection URL to an HTTPS server connection.
OR
Other organizationally defined handling method.

Reload the NGINX server configuration.

pkill -HUP nginx

Alternatively, reinstall Automation Controller for each web server host.'
  impact 0.5
  ref 'DPMS Target Red Hat Ansible Automation Controller Web Server'
  tag check_id: 'C-60638r902401_chk'
  tag severity: 'medium'
  tag gid: 'V-256963'
  tag rid: 'SV-256963r902403_rule'
  tag stig_id: 'APWS-AT-000850'
  tag gtitle: 'SRG-APP-000439-WSR-000151'
  tag fix_id: 'F-60580r902402_fix'
  tag satisfies: ['SRG-APP-000439-WSR-000151', 'SRG-APP-000439-WSR-000152', 'SRG-APP-000442-WSR-000182', 'SRG-APP-000429-WSR-000113']
  tag 'documentable'
  tag cci: ['CCI-002418', 'CCI-002422', 'CCI-002476']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-28 (1)']
end
