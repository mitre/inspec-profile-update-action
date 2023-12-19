control 'SV-221438' do
  title 'OHS must restrict access methods.'
  desc '<0> [object Object]'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "<LimitExcept>" directive at the directory configuration scope.

3. If the "<LimitExcept>" directive is omitted (with the exception of the "<Directory />" directive) or is set improperly, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "<LimitExcept>" directive at the directory configuration scope.

3. Set the "<LimitExcept>" directive to "GET POST", add the directive if it does not exist.

4. Within the "<LimitExcept GET POST>" directives, add the directive "Deny" and set it to "from all".'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23153r414997_chk'
  tag severity: 'medium'
  tag gid: 'V-221438'
  tag rid: 'SV-221438r879887_rule'
  tag stig_id: 'OH12-1X-000200'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23142r414998_fix'
  tag legacy: ['SV-79129', 'V-64639']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
