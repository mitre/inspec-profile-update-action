control 'SV-221432' do
  title 'OHS must be set to evaluate deny directives first when considering whether to serve a file.'
  desc 'Part of securing OHS is allowing/denying access to the web server.  Deciding on the manor the allow/deny rules are evaluated can turn what was once an allowable access into being blocked if the evaluation is reversed.  By ordering the access as first deny and then allow, OHS will deny all access first and then look at the allow clauses to see who may access the server.  By structuring the evaluation in this manner, a misconfiguration will more likely deny a valid user than allow an illegitimate user that may compromise the system.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "<Directory />" directive within the OHS server configuration scope.

3. If the "Order" directive within the "<Directory />" directive is omitted or is set improperly, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "<Directory />" directive within the OHS server configuration scope.

3. Set the "Order" directive within the "<Directory />" directive to "deny,allow", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23147r414979_chk'
  tag severity: 'medium'
  tag gid: 'V-221432'
  tag rid: 'SV-221432r414981_rule'
  tag stig_id: 'OH12-1X-000194'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23136r414980_fix'
  tag 'documentable'
  tag legacy: ['SV-79117', 'V-64627']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
