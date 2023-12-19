control 'SV-78973' do
  title 'OHS must have the Alias /error directive defined to reference the directory accompanying the ErrorDocument directives to minimize the identity of OHS, patches, loaded modules, and directory paths in warning and error messages displayed to clients.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server, backend systems being accessed, and plug-ins or modules being used. 

Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. 

This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "Alias /error/ "${ORACLE_INSTANCE}/config/fmwconfig/components/${COMPONENT_TYPE}/instances/${COMPONENT_NAME}/error/"" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted, this is a finding.

4. Validate that the folder where the directive is pointing is valid. If the folder is not valid, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "Alias /error/ "${ORACLE_INSTANCE}/config/fmwconfig/components/${COMPONENT_TYPE}/instances/${COMPONENT_NAME}/error/"" directive at the OHS server and virtual host configuration scopes.

3. Set the "Alias" directive to "/error/ "${ORACLE_INSTANCE}/config/fmwconfig/components/${COMPONENT_TYPE}/instances/${COMPONENT_NAME}/error/"", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65235r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64483'
  tag rid: 'SV-78973r1_rule'
  tag stig_id: 'OH12-1X-000349'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-70413r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
