control 'SV-221415' do
  title 'OHS must be configured to use a specified IP address, port, and protocol.'
  desc 'The web server must be configured to listen on a specified IP address and port.  Without specifying an IP address and port for the web server to utilize, the web server will listen on all IP addresses available to the hosting server.  If the web server has multiple IP addresses, i.e., a management IP address, the web server will also accept connections on the management IP address.  

Accessing the hosted application through an IP address normally used for non-application functions opens the possibility of user access to resources, utilities, files, ports, and protocols that are protected on the desired application IP address.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for a "Listen" directive at the OHS server configuration scope.

3. If the directive is set without an IP address, port, and protocol specified, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/ssl.conf with an editor.

2. Search for a "Listen" directive at the OHS server configuration scope.

3. Set the "Listen" directive to a value containing an IP address, port, and protocol (e.g., "Listen 123.123.123.123:80 http" or "Listen 456.456.456.456:443 https").'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23130r414928_chk'
  tag severity: 'medium'
  tag gid: 'V-221415'
  tag rid: 'SV-221415r414930_rule'
  tag stig_id: 'OH12-1X-000173'
  tag gtitle: 'SRG-APP-000142-WSR-000089'
  tag fix_id: 'F-23119r414929_fix'
  tag 'documentable'
  tag legacy: ['SV-78895', 'V-64405']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
