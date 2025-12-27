control 'SV-221443' do
  title 'OHS must have the RewriteLogLevel directive set to the proper log level.'
  desc 'Logging must not contain sensitive information or more information necessary than that needed to administer the system.  The log levels from the rewrite engine range from 0 to 9 where 0 is no logging and 9 being the most verbose.  A log level that gives enough information for an investigation if an attack occurs of enough information to troubleshoot issues should be selected.  Too much information makes the system vulnerable and may give attacker information to other resources or data within the hosted applications.'
  desc 'check', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "RewriteLogLevel" directive at the OHS server and virtual host configuration scopes.

3. If the directive is omitted or is not set to "3", this is a finding unless inherited from a larger scope.'
  desc 'fix', '1. As required, open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor that contains a "<VirtualHost>" directive.

2. Search for the "RewriteLogLevel" directive at the OHS server and virtual host configuration scopes.

3. Set the "RewriteLogLevel" directive to "3"; add the directive if it does not exist unless inherited from a larger scope.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23158r415012_chk'
  tag severity: 'low'
  tag gid: 'V-221443'
  tag rid: 'SV-221443r879887_rule'
  tag stig_id: 'OH12-1X-000205'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-23147r415013_fix'
  tag 'documentable'
  tag legacy: ['SV-79139', 'V-64649']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
