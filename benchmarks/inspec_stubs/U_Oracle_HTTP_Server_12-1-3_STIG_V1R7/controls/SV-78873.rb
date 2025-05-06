control 'SV-78873' do
  title 'OHS must have the AddHandler directive disabled.'
  desc "Controlling what a user of a hosted application can access is part of the security posture of the web server. Any time a user can access more functionality than is needed for the operation of the hosted application poses a security issue. A user with too much access can view information that is not needed for the user's job role, or the user could use the function in an unintentional manner.

A MIME tells the web server what type of program various file types and extensions are and what external utilities or programs are needed to execute the file type.

A shell is a program that serves as the basic interface between the user and the operating system, so hosted application users must not have access to these programs. Shell programs may execute shell escapes and can then perform unauthorized activities that could damage the security posture of the web server."
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for "AddHandler" directives at the OHS server, virtual host, and directory configuration scopes.

3. If an "AddHandler" directive exists, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for "AddHandler" directives at the OHS server, virtual host, and directory configuration scopes.

3. If an "AddHandler" directive exists, remove it.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65135r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64383'
  tag rid: 'SV-78873r1_rule'
  tag stig_id: 'OH12-1X-000160'
  tag gtitle: 'SRG-APP-000141-WSR-000081'
  tag fix_id: 'F-70313r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
