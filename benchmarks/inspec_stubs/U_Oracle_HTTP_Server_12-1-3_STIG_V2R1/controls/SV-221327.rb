control 'SV-221327' do
  title 'OHS, behind a load balancer or proxy server, must have a log file defined for each site/virtual host to produce log records containing the client IP information as the source and destination and not the load balancer or proxy IP information with each event.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct source, e.g., source IP, of the events is important during forensic analysis. Correctly determining the source of events will add information to the overall reconstruction of the logable event. By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the source occurred in other areas within the enterprise.

A web server behind a load balancer or proxy server, when not configured correctly, will record the load balancer or proxy server as the source of every logable event. When looking at the information forensically, this information is not helpful in the investigation of events. The web server must record with each event the client source of the event.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "CustomLog" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or set improperly, this is a finding unless inherited from a larger scope.

4. Validate that the folder specified exists.  If the folder does not exist, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "CustomLog" directive at the OHS server and virtual host configuration scopes.

3a. If the virtual host is NOT configured for SSL, set the "CustomLog" directive to ""||${PRODUCT_HOME}/bin/odl_rotatelogs <DESIRED_DIRECTORY_AND_FILE_NAME> 43200" dod", add the directive if it does not exist unless inherited from a larger scope.
3b. If the virtual host is configured for SSL, set the "CustomLog" directive to ""||${PRODUCT_HOME}/bin/odl_rotatelogs <DESIRED_DIRECTORY_AND_FILE_NAME> 43200" dod_ssl", add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23042r414664_chk'
  tag severity: 'medium'
  tag gid: 'V-221327'
  tag rid: 'SV-221327r539625_rule'
  tag stig_id: 'OH12-1X-000065'
  tag gtitle: 'SRG-APP-000098-WSR-000060'
  tag fix_id: 'F-23031r414665_fix'
  tag 'documentable'
  tag legacy: ['SV-78711', 'V-64221']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
