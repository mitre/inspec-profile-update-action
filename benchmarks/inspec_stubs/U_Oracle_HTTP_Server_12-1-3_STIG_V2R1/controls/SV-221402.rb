control 'SV-221402' do
  title 'OHS must disable the directive pointing to the directory containing the OHS manuals.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server because this type of code has not been evaluated and approved. A production web server must only contain components that are operationally necessary (e.g., compiled code, scripts, web-content, etc.). 

Any documentation, sample code, example applications, and tutorials must be removed from a production web server. To make certain that the documentation and code are not installed or uninstalled completely; the web server must offer an option as part of the installation process to exclude these packages or to uninstall the packages if necessary.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for a "<Directory "${PRODUCT_HOME}/manual">" directive at the OHS server configuration scope.

3. If the directive and the directives it contains exists and is not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for a "<Directory "${PRODUCT_HOME}/manual">" directive at the OHS server configuration scope.

3. Comment out the "<Directory "${PRODUCT_HOME}/manual">" directive and any directives it contains if they exist.'
  impact 0.3
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23117r414889_chk'
  tag severity: 'low'
  tag gid: 'V-221402'
  tag rid: 'SV-221402r414891_rule'
  tag stig_id: 'OH12-1X-000156'
  tag gtitle: 'SRG-APP-000141-WSR-000077'
  tag fix_id: 'F-23106r414890_fix'
  tag 'documentable'
  tag legacy: ['SV-78869', 'V-64379']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
