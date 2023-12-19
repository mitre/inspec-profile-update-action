control 'SV-79115' do
  title 'OHS must have the AllowOverride directive set properly.'
  desc 'The property "AllowOverride" is used to allow directives to be set differently than those set for the overall architecture.  When the property is not set to "None", OHS will check for directives in the htaccess files at each directory level until the requested resource is found for each URL request.  Allowing parameters to be overridden at different levels of an application becomes a security risk as the overall security of the hosted application can change dependencies on the URL being accessed.  Security management also becomes difficult as a misconfiguration can be mistakenly made.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "AllowOverride" directive at the directory configuration scope.

3. If the "AllowOverride" directive is omitted or is not set to "None", this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "AllowOverride" directive at the directory configuration scope.

3. Set the "AllowOverride" directive to "None", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65367r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64625'
  tag rid: 'SV-79115r1_rule'
  tag stig_id: 'OH12-1X-000193'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70555r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
