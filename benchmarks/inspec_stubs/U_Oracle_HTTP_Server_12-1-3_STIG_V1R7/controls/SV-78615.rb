control 'SV-78615' do
  title 'OHS must have the mpm_prefork_module directive disabled so as not conflict with the worker directive used to limit the number of allowed simultaneous requests.'
  desc 'Web server management includes the ability to control the number of users and user sessions that utilize a web server. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to several types of Denial of Service attacks. 

Although there is some latitude concerning the settings themselves, the settings should follow DoD-recommended values, but the settings should be configurable to allow for future DoD direction. While the DoD will specify recommended values, the values can be adjusted to accommodate the operational requirement of a given system.'
  desc 'check', '1. Open the $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf file with an editor.

2. Search for the "<IfModule mpm_prefork_module>" directive at the OHS server configuration scope.

3. If this directive is found and not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "<IfModule mpm_prefork_module>" directive at the OHS server configuration scope.

3. Comment out the "<IfModule mpm_prefork_module>" directive and any directives that it contains.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-64875r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64125'
  tag rid: 'SV-78615r1_rule'
  tag stig_id: 'OH12-1X-000002'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-70053r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
