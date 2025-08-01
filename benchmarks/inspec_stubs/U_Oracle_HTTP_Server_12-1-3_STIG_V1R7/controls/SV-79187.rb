control 'SV-79187' do
  title 'The OHS DocumentRoot directory must be on a separate partition from OS root partition.'
  desc 'Application partitioning enables an additional security measure by securing user traffic under one security context, while managing system and application files under another. Web content is accessible to an anonymous web user. For such an account to have access to system files of any type is a major security risk that is avoidable and desirable. Failure to partition the system files from the web site documents increases risk of attack via directory traversal, or impede web site availability due to drive space exhaustion.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "DocumentRoot" directive at the OHS server and virtual host configuration scopes.

3. If the directory associated with the "DocumentRoot" directive is associated with the root partition, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "DocumentRoot" directive at the OHS server and virtual host configuration scopes.

3. Move the directory associated with the "DocumentRoot" directive to a partition different from root partition.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65439r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64697'
  tag rid: 'SV-79187r1_rule'
  tag stig_id: 'OH12-1X-000230'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70627r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
