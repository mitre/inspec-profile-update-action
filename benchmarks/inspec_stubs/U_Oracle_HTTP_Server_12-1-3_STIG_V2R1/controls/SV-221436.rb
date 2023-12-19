control 'SV-221436' do
  title 'OHS must have the HostnameLookups directive enabled.'
  desc 'Setting the "HostnameLookups" to "On" allows for more information to be logged in the event of an attack and subsequent investigation.  This information can be added to other information gathered to narrow the attacker location.  The DNS name can also be used for filtering access to the OHS hosted applications by denying particular types of hostnames.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "HostnameLookups" directive at the server, virtual host, and directory configuration scopes.

3. If the "HostnameLookups" directive is omitted or is not set to "On", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "HostnameLookups" directive at the server, virtual host, and directory configuration scopes.

3. Set the "HostnameLookups" directive to "On", add the directive if it does not exist.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23151r414991_chk'
  tag severity: 'low'
  tag gid: 'V-221436'
  tag rid: 'SV-221436r414993_rule'
  tag stig_id: 'OH12-1X-000198'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23140r414992_fix'
  tag 'documentable'
  tag legacy: ['SV-79125', 'V-64635']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
