control 'SV-78705' do
  title 'OHS must have a log file defined for each site/virtual host to capture logs generated that allow the establishment of the source of events.'
  desc 'Web server logging capability is critical for accurate forensic analysis. Without sufficient and accurate information, a correct replay of the events cannot be determined. 

Ascertaining the correct source, e.g., source IP, of the events is important during forensic analysis. Correctly determining the source will add information to the overall reconstruction of the logable event. By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if the event compromised other assets within the enterprise.

Without sufficient information establishing the source of the logged event, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.'
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
  tag check_id: 'C-64967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64215'
  tag rid: 'SV-78705r1_rule'
  tag stig_id: 'OH12-1X-000062'
  tag gtitle: 'SRG-APP-000098-WSR-000059'
  tag fix_id: 'F-70145r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
