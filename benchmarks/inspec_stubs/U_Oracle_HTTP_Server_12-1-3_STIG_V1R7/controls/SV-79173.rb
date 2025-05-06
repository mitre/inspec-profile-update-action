control 'SV-79173' do
  title 'The OHS document root directory must not be on a network share.'
  desc 'Sharing of web server content is a security risk when a web server is involved. Users accessing the share anonymously could experience privileged access to the content of such directories. Network sharable directories expose those directories and their contents to unnecessary access. Any unnecessary exposure increases the risk that someone could exploit that access and either compromises the web content or cause web server performance problems.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "DocumentRoot" directive at the OHS server and virtual host configuration scopes.

3. If the directive value is used as a network share (e.g., ps -ef | grep nfs, ps -ef | grep smb, etc.), this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "DocumentRoot" directive at the OHS server and virtual host configuration scopes.

3. Remove the shares that are associated with any directory specified as a value for the "DocumentRoot" directives.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65425r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64683'
  tag rid: 'SV-79173r1_rule'
  tag stig_id: 'OH12-1X-000223'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70613r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
