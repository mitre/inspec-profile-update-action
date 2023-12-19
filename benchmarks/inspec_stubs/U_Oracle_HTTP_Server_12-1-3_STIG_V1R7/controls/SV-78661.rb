control 'SV-78661' do
  title 'OHS must have a log file defined for each site/virtual host to capture information to be used by external applications or entities to monitor and control remote access.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions. 

By providing remote access information to an external monitoring system, the organization can monitor for cyber attacks and monitor compliance with remote access policies. The organization can also look at data organization wide and determine an attack or anomaly is occurring on the organization which might not be noticed if the data were kept local to the web server.

Examples of external applications used to monitor or control access would be audit log monitoring systems, dynamic firewalls, or infrastructure monitoring systems.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "CustomLog" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or set improperly, this is a finding unless inherited from a larger scope.

4. Validate that the folder specified exists.  If the folder does not exist, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "CustomLog" directive at the OHS server and virtual host configuration scopes.

3a. If the virtual host is NOT configured for SSL, set the "CustomLog" directive to ""||${PRODUCT_HOME}/bin/odl_rotatelogs <DESIRED_DIRECTORY_AND_FILE_NAME> 43200" dod", add the directive if it does not exist unless inherited from a larger scope.
3b. If the virtual host is configured for SSL, set the "CustomLog" directive to ""||${PRODUCT_HOME}/bin/odl_rotatelogs <DESIRED_DIRECTORY_AND_FILE_NAME> 43200" dod_ssl", add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-64923r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64171'
  tag rid: 'SV-78661r1_rule'
  tag stig_id: 'OH12-1X-000026'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag fix_id: 'F-70101r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
