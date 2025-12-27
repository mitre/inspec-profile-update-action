control 'SV-221276' do
  title 'OHS must limit the number of worker processes to limit the number of allowed simultaneous requests.'
  desc 'Web server management includes the ability to control the number of users and user sessions that utilize a web server. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to several types of Denial of Service attacks. 

Although there is some latitude concerning the settings themselves, the settings should follow DoD-recommended values, but the settings should be configurable to allow for future DoD direction. While the DoD will specify recommended values, the values can be adjusted to accommodate the operational requirement of a given system.'
  desc 'check', '1. Open the $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf file with an editor.

2. Search for the "ServerLimit" directive within "<IfModule mpm_worker_module>" directive at the OHS server configuration scope.

3. If "ServerLimit" is omitted or set greater than the maximum of "16" and the calculation of "MaxClients"/"ThreadsPerChild", this is a finding.

Note: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for the use of a higher value. If the site has this documentation, this should be marked as not a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "ServerLimit" directive within "<IfModule mpm_worker_module>" directive at the OHS server configuration scope.

3. Within the "<IfModule mpm_worker_module>" directive, set the "ServerLimit" directive to the maximum of "16" and the calculation of "MaxClients"/"ThreadsPerChild" immediately before the "MaxClients" directive, add the directive if it does not exist.

Note: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for the use of a higher value.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-22991r414511_chk'
  tag severity: 'medium'
  tag gid: 'V-221276'
  tag rid: 'SV-221276r879511_rule'
  tag stig_id: 'OH12-1X-000005'
  tag gtitle: 'SRG-APP-000001-WSR-000001'
  tag fix_id: 'F-22980r414512_fix'
  tag 'documentable'
  tag legacy: ['SV-78621', 'V-64131']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
