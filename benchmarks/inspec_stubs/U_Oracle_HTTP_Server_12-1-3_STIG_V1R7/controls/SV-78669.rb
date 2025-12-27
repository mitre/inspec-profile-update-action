control 'SV-78669' do
  title 'OHS must have a log level severity defined to generate adequate log records for system startup and shutdown, system access, and system authentication events.'
  desc 'Log records can be generated from various components within the web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific web server functionalities may be logged as well. The web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the web server must be able to facilitate these changes.

The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events. If these events are not logged at a minimum, any type of forensic investigation would be missing pertinent information needed to replay what occurred.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogSeverity" directive at the OHS server configuration scope.

3. If the directive is omitted or is not set to "NOTIFICATION:32", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogSeverity" directive at the OHS server configuration scope.

3. Set the "OraLogSeverity" directive to "NOTIFICATION:32", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-64931r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64179'
  tag rid: 'SV-78669r1_rule'
  tag stig_id: 'OH12-1X-000043'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-70109r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
