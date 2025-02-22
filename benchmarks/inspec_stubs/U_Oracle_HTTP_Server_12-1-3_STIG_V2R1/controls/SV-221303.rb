control 'SV-221303' do
  title 'OHS must have the client requests logging module loaded to generate log records for system startup and shutdown, system access, and system authentication logging.'
  desc 'Log records can be generated from various components within the web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific web server functionalities may be logged as well. The web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the web server must be able to facilitate these changes.

The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events. If these events are not logged at a minimum, any type of forensic investigation would be missing pertinent information needed to replay what occurred.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule log_config_module" directive at the OHS server configuration scope.

3. If the directive is omitted, this is a finding.

4. Validate that the file specified exist.  If the file does not exist, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule log_config_module" directive at the OHS server configuration scope.

3. Set the "LoadModule log_config_module" directive to ""${PRODUCT_HOME}/modules/mod_log_config.so"", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23018r414592_chk'
  tag severity: 'medium'
  tag gid: 'V-221303'
  tag rid: 'SV-221303r414594_rule'
  tag stig_id: 'OH12-1X-000040'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-23007r414593_fix'
  tag 'documentable'
  tag legacy: ['SV-78663', 'V-64173']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
