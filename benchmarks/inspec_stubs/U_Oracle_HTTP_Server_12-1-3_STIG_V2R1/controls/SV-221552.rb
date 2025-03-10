control 'SV-221552' do
  title 'OHS must have production information removed from error documents to minimize the identity of OHS, patches, loaded modules, and directory paths in warning and error messages displayed to clients.'
  desc 'Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server, backend systems being accessed, and plug-ins or modules being used. 

Web servers will often display error messages to client users displaying enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. 

This information could be used by an attacker to blueprint what type of attacks might be successful. The information given to users must be minimized to not aid in the blueprinting of the web server.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "Alias /error/ "${ORACLE_INSTANCE}/config/fmwconfig/components/${COMPONENT_TYPE}/instances/${COMPONENT_NAME}/error/"", "Directory "${ORACLE_INSTANCE}/config/fmwconfig/components/${COMPONENT_TYPE}/instances/{COMPONENT_NAME}/error"", and "ErrorDocument" directives at the OHS server, virtual host, and directory configuration scopes.

3. For every file specified by an "ErrorDocument" directive, check the file exists and its contents to determine whether any OHS product information is present.

4. If OHS product information is present in the file(s), this is a finding.'
  desc 'fix', '1. Go to the directory specified by the "Alias /error/" directive in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf.  (e.g., cd $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/<componentName>/error).

2. Change the extension of each file located in $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/<componentName>/error from .html.var to .html (e.g., mv HTTP_NOT_FOUND.hmtl.var HTTP_NOT_FOUND_en.html).

3. Modify the content of each file to be static such that mod_include and mod_negotiation are not needed and that no OHS product information is discernable by a user encountering the error.

4. Set the appropriate "ErrorDocument" directives in $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf to reference the appropriate file in $DOMAIN_HOME/config/fmwconfig/components/OHS/instances/<componentName>/httpd.conf, add the directives if they do not exist.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23267r415335_chk'
  tag severity: 'low'
  tag gid: 'V-221552'
  tag rid: 'SV-221552r415337_rule'
  tag stig_id: 'OH12-1X-000352'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-23256r415336_fix'
  tag 'documentable'
  tag legacy: ['SV-78979', 'V-64489']
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
