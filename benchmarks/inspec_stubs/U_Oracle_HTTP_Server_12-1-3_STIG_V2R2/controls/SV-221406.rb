control 'SV-221406' do
  title 'OHS must have the LoadModule cgid_module directive disabled.'
  desc 'Scripts allow server side processing on behalf of the hosted application user or as processes needed in the implementation of hosted applications. Removing scripts not needed for application operation or deemed vulnerable helps to secure the web server. 

To assure scripts are not added to the web server and run maliciously, those script mappings that are not needed or used by the web server for hosted application operation must be removed.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule cgid_module" directive within the "<IfModule mpm_worker_module>" directive at the OHS server configuration scope.

3. If the directive and its surrounding "<IfModule mpm_worker_module>" directive exist and are not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for the "LoadModule cgid_module" directive within the "<IfModule mpm_worker_module>" directive at the OHS server configuration scope.

3. Comment out the "LoadModule cgid_module" directive and surrounding "<IfModule mpm_worker_module>" directives if they exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23121r414901_chk'
  tag severity: 'medium'
  tag gid: 'V-221406'
  tag rid: 'SV-221406r879587_rule'
  tag stig_id: 'OH12-1X-000162'
  tag gtitle: 'SRG-APP-000141-WSR-000082'
  tag fix_id: 'F-23110r414902_fix'
  tag 'documentable'
  tag legacy: ['V-64387', 'SV-78877']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
