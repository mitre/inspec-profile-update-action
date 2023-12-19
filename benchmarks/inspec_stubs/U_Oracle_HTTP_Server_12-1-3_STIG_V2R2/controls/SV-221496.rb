control 'SV-221496' do
  title 'OHS must have the DocumentRoot directive set to a separate partition from the OHS system files.'
  desc 'A web server is used to deliver content on the request of a client. The content delivered to a client must be controlled, allowing only hosted application files to be accessed and delivered. To allow a client access to system files of any type is a major security risk that is entirely avoidable. Obtaining such access is the goal of directory traversal and URL manipulation vulnerabilities. To facilitate such access by misconfiguring the web document (home) directory is a serious error. In addition, having the path on the same drive as the system folder compounds potential attacks such as drive space exhaustion.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "DocumentRoot" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or set improperly, this is a finding.

4. Validate that the directory specified exists. If the directory does not exist, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "DocumentRoot" directive at the OHS server and virtual host configuration scopes.

3. Set the "DocumentRoot" directive to a location that is on a separate drive from the $ORACLE_HOME and $DOMAIN_HOME directories.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23211r415171_chk'
  tag severity: 'medium'
  tag gid: 'V-221496'
  tag rid: 'SV-221496r879643_rule'
  tag stig_id: 'OH12-1X-000281'
  tag gtitle: 'SRG-APP-000233-WSR-000146'
  tag fix_id: 'F-23200r415172_fix'
  tag 'documentable'
  tag legacy: ['SV-78941', 'V-64451']
  tag cci: ['CCI-001084']
  tag nist: ['SC-3']
end
