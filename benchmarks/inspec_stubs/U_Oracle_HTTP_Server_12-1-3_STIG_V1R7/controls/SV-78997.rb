control 'SV-78997' do
  title 'OHS must be configured to store access log files to an appropriate storage device from which other tools can be configured to reference those log files for diagnostic/forensic purposes.'
  desc 'A web server will typically utilize logging mechanisms for maintaining a historical log of activity that occurs within a hosted application. This information can then be used for diagnostic purposes, forensics purposes, or other purposes relevant to ensuring the availability and integrity of the hosted application.

While it is important to log events identified as being critical and relevant to security, it is equally important to notify the appropriate personnel in a timely manner so they are able to respond to events as they occur. 

Manual review of the web server logs may not occur in a timely manner, and each event logged is open to interpretation by a reviewer. By integrating the web server into an overall or organization-wide log review, a larger picture of events can be viewed, and analysis can be done in a timely and reliable manner.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "CustomLog" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or set improperly, this is a finding unless inherited from a larger scope.

4. Validate that the folder specified exists.  If the folder does not exist, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "CustomLog" directive at the OHS server and virtual host configuration scopes.

3a. If the virtual host is NOT configured for SSL, set the "CustomLog" directive to ""||${PRODUCT_HOME}/bin/odl_rotatelogs <DESIRED_DIRECTORY_AND_FILE_NAME> 43200" dod", add the directive if it does not exist unless inherited from a larger scope and reference a location where other tools can access the log files for diagnostic/forensic purposes.
3b. If the virtual host is configured for SSL, set the "CustomLog" directive to ""||${PRODUCT_HOME}/bin/odl_rotatelogs <DESIRED_DIRECTORY_AND_FILE_NAME> 43200" dod_ssl", add the directive if it does not exist unless inherited from a larger scope and reference a location where other tools can access the log files for diagnostic/forensic purposes.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65259r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64507'
  tag rid: 'SV-78997r1_rule'
  tag stig_id: 'OH12-1X-000082'
  tag gtitle: 'SRG-APP-000358-WSR-000163'
  tag fix_id: 'F-70437r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
