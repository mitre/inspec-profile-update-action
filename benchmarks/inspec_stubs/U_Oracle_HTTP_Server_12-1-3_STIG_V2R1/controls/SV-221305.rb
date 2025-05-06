control 'SV-221305' do
  title 'OHS must have a log directory location defined to generate log records for system startup and shutdown, system access, and system authentication logging.'
  desc 'Log records can be generated from various components within the web server (e.g., httpd, plug-ins to external backends, etc.). From a web server perspective, certain specific web server functionalities may be logged as well. The web server must allow the definition of what events are to be logged. As conditions change, the number and types of events to be logged may change, and the web server must be able to facilitate these changes.

The minimum list of logged events should be those pertaining to system startup and shutdown, system access, and system authentication events. If these events are not logged at a minimum, any type of forensic investigation would be missing pertinent information needed to replay what occurred.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogDir" directive at the OHS server configuration scope.

3. If the directive is omitted, this is a finding.

4. Validate that the folder specified exists.  If the folder does not exist, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "OraLogDir" directive at the OHS server configuration scope.

3. Set the "OraLogDir" directive to an appropriate, protected location on a partition with sufficient space that is different from the partition on which the OHS software is installed; add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23020r414598_chk'
  tag severity: 'medium'
  tag gid: 'V-221305'
  tag rid: 'SV-221305r414600_rule'
  tag stig_id: 'OH12-1X-000042'
  tag gtitle: 'SRG-APP-000089-WSR-000047'
  tag fix_id: 'F-23009r414599_fix'
  tag 'documentable'
  tag legacy: ['SV-78667', 'V-64177']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
