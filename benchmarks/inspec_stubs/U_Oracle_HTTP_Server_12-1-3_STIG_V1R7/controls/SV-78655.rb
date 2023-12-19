control 'SV-78655' do
  title 'OHS must have the log rotation parameter set to allow generated information to be used by external applications or entities to monitor and control remote access.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions. 

By providing remote access information to an external monitoring system, the organization can monitor for cyber attacks and monitor compliance with remote access policies. The organization can also look at data organization wide and determine an attack or anomaly is occurring on the organization which might not be noticed if the data were kept local to the web server.

Examples of external applications used to monitor or control access would be audit log monitoring systems, dynamic firewalls, or infrastructure monitoring systems.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogRotationParams" directive at the OHS server configuration scope.

3. If the directive is omitted or set improperly, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogRotationParams" directive at the OHS server configuration scope.

3. As required, set the "OraLogRotationParams" directive to satisfy the NIST 800-92 logging requirements, add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-64917r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64165'
  tag rid: 'SV-78655r1_rule'
  tag stig_id: 'OH12-1X-000023'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag fix_id: 'F-70095r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
