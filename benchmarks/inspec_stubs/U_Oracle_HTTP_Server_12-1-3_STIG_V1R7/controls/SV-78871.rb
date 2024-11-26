control 'SV-78871' do
  title 'OHS must have the AliasMatch directive disabled for the OHS manuals.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server because this type of code has not been evaluated and approved. A production web server must only contain components that are operationally necessary (e.g., compiled code, scripts, web-content, etc.). 

Any documentation, sample code, example applications, and tutorials must be removed from a production web server. To make certain that the documentation and code are not installed or uninstalled completely; the web server must offer an option as part of the installation process to exclude these packages or to uninstall the packages if necessary.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for a "AliasMatch ^/manual(?:/(?:de|en|es|fr|ja|ko|pt-br|ru|tr))?(/.*)?$ "${PRODUCT_HOME}/manual$1"" directive at the OHS server configuration scope.

3. If the directive exists and is not commented out, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf with an editor.

2. Search for an "AliasMatch ^/manual(?:/(?:de|en|es|fr|ja|ko|pt-br|ru|tr))?(/.*)?$ "${PRODUCT_HOME}/manual$1"" directive at the OHS server configuration scope.

3. Comment out the "AliasMatch ^/manual(?:/(?:de|en|es|fr|ja|ko|pt-br|ru|tr))?(/.*)?$ "${PRODUCT_HOME}/manual$1"" directive if it exists.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65133r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64381'
  tag rid: 'SV-78871r1_rule'
  tag stig_id: 'OH12-1X-000157'
  tag gtitle: 'SRG-APP-000141-WSR-000077'
  tag fix_id: 'F-70311r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
