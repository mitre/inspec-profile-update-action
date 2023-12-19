control 'SV-221441' do
  title 'OHS must have the RewriteEngine directive enabled.'
  desc 'The rewrite engine is used to evaluate URL requests and modify the requests on the fly.  Enabling this engine gives the system administrator the capability to trap potential attacks before reaching the hosted applications or to modify the URL to fix issues in the request before forwarding to the applications.  The rewrite engine becomes a pre-filtering tool to fix data issues before reaching the hosted applications where the URL format or data within the URL could cause buffer overflows, redirection or mobile code snippets that could become an issue if not filtered.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "RewriteEngine" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or is not set to "On", this is a finding unless inherited from a larger scope.'
  desc 'fix', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "RewriteEngine" directive at the OHS server and virtual host configuration scopes.

3. Set the "RewriteEngine" directive to "On", add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23156r415006_chk'
  tag severity: 'low'
  tag gid: 'V-221441'
  tag rid: 'SV-221441r415008_rule'
  tag stig_id: 'OH12-1X-000203'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23145r415007_fix'
  tag 'documentable'
  tag legacy: ['SV-79135', 'V-64645']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
