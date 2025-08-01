control 'SV-221297' do
  title 'Remote access to OHS must follow access policy or work in conjunction with enterprise tools designed to enforce policy requirements.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be able to enforce remote access policy requirements or work in conjunction with enterprise tools designed to enforce policy requirements. 

Examples of the web server enforcing a remote access policy are implementing IP filtering rules, using https instead of http for communication, implementing secure tokens, and validating users.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Review the directives (e.g., "<VirtualHost>", "<Directory>", and "<Location>") at the OHS server and virtual host configuration scopes.

3. If these directives do not contain the appropriate access protection via secure authentication, SSL-associated directives, or "Order", "Deny", and "Allow" directives to secure access or prohibit access from nonsecure zones, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Review the directives (e.g., "<VirtualHost>", "<Directory>", and "<Location>") at the OHS server and virtual host configuration scopes.

3. Configure the web server to require secure authentication as required, use SSL, and/or restrict access from nonsecure zones via "Order", "Deny", and "Allow" directives.

Note: A product such as Oracle Access Manager may facilitate satisfying these requirements.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23012r414574_chk'
  tag severity: 'medium'
  tag gid: 'V-221297'
  tag rid: 'SV-221297r879692_rule'
  tag stig_id: 'OH12-1X-000030'
  tag gtitle: 'SRG-APP-000315-WSR-000003'
  tag fix_id: 'F-23001r414575_fix'
  tag 'documentable'
  tag legacy: ['SV-78983', 'V-64493']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
