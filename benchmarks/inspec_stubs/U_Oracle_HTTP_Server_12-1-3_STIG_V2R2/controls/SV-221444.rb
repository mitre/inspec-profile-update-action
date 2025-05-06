control 'SV-221444' do
  title 'OHS must have the RewriteLog directive set properly.'
  desc 'Specifying where the log files are written gives the system administrator the capability to store the files in a location other than the default, with system files or in a globally accessible location.  The system administrator can also specify a location that is accessible by any enterprise tools that may use the logged data to give a picture of the overall enterprise security posture.  If a file is not specified, OHS will still generate the log data, but it is not written and therefore, cannot be used to monitor the system or for forensic analysis.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "RewriteLog" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or set improperly, this is a finding unless inherited from a larger scope.

4. Validate that the folder specified exists. If the folder does not exist, this is a finding.'
  desc 'fix', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "RewriteLog" directive at the OHS server and virtual host configuration scopes.

3. Set the "RewriteLog" directive to the same location as the "CustomLog" directive; add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23159r415015_chk'
  tag severity: 'low'
  tag gid: 'V-221444'
  tag rid: 'SV-221444r879887_rule'
  tag stig_id: 'OH12-1X-000206'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23148r415016_fix'
  tag 'documentable'
  tag legacy: ['SV-79141', 'V-64651']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
