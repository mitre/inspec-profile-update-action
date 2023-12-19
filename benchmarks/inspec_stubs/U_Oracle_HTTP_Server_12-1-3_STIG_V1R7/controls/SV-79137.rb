control 'SV-79137' do
  title 'OHS must have the RewriteOptions directive set properly.'
  desc 'The rules for the rewrite engine can be configured to inherit those from the parent and build upon that set of rules, to copy the rules from the parent if there are none defined or to only process the rules if the input is a URL.  Of these, the most secure is to inherit from the parent because of how this implemented.  The rules for the current configuration, process or directory, are loaded and then the parent are overlaid.  This means that the parent rule will always override the child rule.  This gives the server a more consistent security configuration.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "RewriteOptions" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or is not set to "inherit", this is a finding unless inherited from a larger scope.'
  desc 'fix', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "RewriteOptions" directive at the OHS server and virtual host configuration scopes.

3. Set the "RewriteOptions" directive to "inherit", add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65389r1_chk'
  tag severity: 'low'
  tag gid: 'V-64647'
  tag rid: 'SV-79137r1_rule'
  tag stig_id: 'OH12-1X-000204'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70577r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
