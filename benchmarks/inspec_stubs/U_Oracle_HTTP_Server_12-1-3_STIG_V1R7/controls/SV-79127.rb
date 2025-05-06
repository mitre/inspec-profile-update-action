control 'SV-79127' do
  title 'OHS must have the ServerAdmin directive set properly.'
  desc 'Making sure that information is given to the system administrator in a timely fashion is important.  This information can be system status, warnings that may need attention before system failure or actual failure notification.  Having this information sent to the system administrator when the issue arises allows for the system administrator to quickly take action and avoid potential DoS for customers.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "ServerAdmin" directive at the server and virtual host configuration scopes.

3. If the "ServerAdmin" directive is omitted or is set improperly, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "ServerAdmin" directive at the virtual host and directory configuration scopes.

3. Set the "ServerAdmin" directive to an appropriate service-based email address for the organization, add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65379r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64637'
  tag rid: 'SV-79127r1_rule'
  tag stig_id: 'OH12-1X-000199'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70567r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
