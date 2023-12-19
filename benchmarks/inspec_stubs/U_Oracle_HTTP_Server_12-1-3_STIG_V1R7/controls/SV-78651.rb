control 'SV-78651' do
  title 'OHS must have a log directory location defined to generate information for use by external applications or entities to monitor and control remote access.'
  desc 'Remote access to the web server is any access that communicates through an external, non-organization-controlled network. Remote access can be used to access hosted applications or to perform management functions. 

By providing remote access information to an external monitoring system, the organization can monitor for cyber attacks and monitor compliance with remote access policies. The organization can also look at data organization wide and determine an attack or anomaly is occurring on the organization which might not be noticed if the data were kept local to the web server.

Examples of external applications used to monitor or control access would be audit log monitoring systems, dynamic firewalls, or infrastructure monitoring systems.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogDir" directive at the OHS server configuration scope.

3. If the directive is omitted, this is a finding.

4. Validate that the folder specified exists.  If the folder does not exist, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogDir" directive at the OHS server configuration scope.

3. Set the "OraLogDir" directive to an appropriate, protected location on a partition with sufficient space that is different from the partition on which the OHS software is installed; add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-64913r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64161'
  tag rid: 'SV-78651r1_rule'
  tag stig_id: 'OH12-1X-000021'
  tag gtitle: 'SRG-APP-000016-WSR-000005'
  tag fix_id: 'F-70091r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
