control 'SV-78985' do
  title 'OHS must have the Order, Allow, and Deny directives set within the Directory directives set to restrict inbound connections from nonsecure zones.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions.

A web server can be accessed remotely and must be capable of restricting access from what the DoD defines as nonsecure zones. Nonsecure zones are defined as any IP, subnet, or region that is defined as a threat to the organization. The nonsecure zones must be defined for public web servers logically located in a DMZ, as well as private web servers with perimeter protection devices. By restricting access from nonsecure zones, through internal web server access list, the web server can stop or slow denial of service (DoS) attacks on the web server.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "<Directory>" directive at the OHS server and virtual host configuration scopes.

Note: This check does not apply to the root directory, i.e. the <Directory /> directive.

3. If the "<Directory>" directive does not contain the appropriate "Order", "Deny", and "Allow" directives to prohibit access from nonsecure zones, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "<Directory>" directive at the OHS server and virtual host configuration scopes.

Note: This fix does not apply to the root directory, i.e. the <Directory /> directive.

3. Set the "Order" directive to "allow,deny", add the directive if it does not exist.

4. Set "Allow" directives to "from all" or to an IP range (e.g., "from 123.123"), add the directives if they do not exist.

5. Set "Deny" directives to an IP range (e.g., "from 123.123") to specify nonsecure zones, add the directives if they do not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65247r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64495'
  tag rid: 'SV-78985r1_rule'
  tag stig_id: 'OH12-1X-000031'
  tag gtitle: 'SRG-APP-000315-WSR-000004'
  tag fix_id: 'F-70425r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
