control 'SV-221466' do
  title 'The OHS DocumentRoot directory must be in a separate partition from the OHS ServerRoot directory.'
  desc 'Application partitioning enables an additional security measure by securing user traffic under one security context, while managing system and application files under another. Web content is accessible to an anonymous web user. For such an account to have access to system files of any type is a major security risk that is avoidable and desirable. Failure to partition the system files from the web site documents increases risk of attack via directory traversal, or impede web site availability due to drive space exhaustion.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "DocumentRoot" directive at the OHS server and virtual host configuration scopes.

3. Search for the "ServerRoot" directive at the OHS server configuration scope.

4. If the "DocumentRoot" directive value specifies a directory on the same partition as the directory specified in the "ServerRoot" directive, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "DocumentRoot" directive at the OHS server and virtual host configuration scopes.

3. Search for the "ServerRoot" directive at the OHS server configuration scope.

4. Move the directory associated with the "DocumentRoot" directive to a partition different from the partition associated with the directory specified by the "ServerRoot" directive.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23181r415081_chk'
  tag severity: 'medium'
  tag gid: 'V-221466'
  tag rid: 'SV-221466r415083_rule'
  tag stig_id: 'OH12-1X-000229'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23170r415082_fix'
  tag 'documentable'
  tag legacy: ['SV-79185', 'V-64695']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
