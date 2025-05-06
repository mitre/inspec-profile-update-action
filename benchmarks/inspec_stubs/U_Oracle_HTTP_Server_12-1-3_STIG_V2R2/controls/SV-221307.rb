control 'SV-221307' do
  title 'OHS must have the log rotation parameter set to allow for the generation log records for system startup and shutdown, system access, and system authentication events.'
  desc 'Log records can be generated from various components within the web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific web server functionalities may be logged as well. The web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the web server must be able to facilitate these changes.

The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events. If these events are not logged at a minimum, any type of forensic investigation would be missing pertinent information needed to replay what occurred.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogRotationParams" directive at the OHS server configuration scope.

3. If the directive is omitted or set improperly, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogRotationParams" directive at the OHS server configuration scope.

3. As required, set the "OraLogRotationParams" directive to satisfy the NIST 800-92 logging requirements, add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23022r414604_chk'
  tag severity: 'medium'
  tag gid: 'V-221307'
  tag rid: 'SV-221307r879559_rule'
  tag stig_id: 'OH12-1X-000044'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-23011r414605_fix'
  tag 'documentable'
  tag legacy: ['SV-78671', 'V-64181']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
