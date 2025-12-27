control 'SV-221290' do
  title 'OHS must have the OraLogMode set to Oracle Diagnostic Logging text mode to generate information to be used by external applications or entities to monitor and control remote access.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions. 

By providing remote access information to an external monitoring system, the organization can monitor for cyber attacks and monitor compliance with remote access policies. The organization can also look at data organization wide and determine an attack or anomaly is occurring on the organization which might not be noticed if the data were kept local to the web server.

Examples of external applications used to monitor or control access would be audit log monitoring systems, dynamic firewalls, or infrastructure monitoring systems.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogMode" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "odl-text", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogMode" directive at the OHS server configuration scope.

3. Set the "OraLogMode" directive to "odl-text", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23005r414553_chk'
  tag severity: 'medium'
  tag gid: 'V-221290'
  tag rid: 'SV-221290r879521_rule'
  tag stig_id: 'OH12-1X-000020'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag fix_id: 'F-22994r414554_fix'
  tag 'documentable'
  tag legacy: ['SV-78649', 'V-64159']
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
