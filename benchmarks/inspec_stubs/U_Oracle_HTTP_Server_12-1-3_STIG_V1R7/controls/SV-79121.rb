control 'SV-79121' do
  title 'The OHS instance installation must not contain an .htaccess file.'
  desc '.htaccess files are used to override settings in the OHS configuration files.  The placement of the .htaccess file is also important as the settings will affect the directory where the file is located and any subdirectories below.  Allowing the use of .htaccess files, the hosted application security posture and overall OHS posture could change dependent on the URL being accessed.  Allowing the override of parameters in .htaccess files makes it difficult to truly know the security posture of the system and it also makes it difficult to understand what the security posture may have been if an attack is successful.  To thwart the overriding of parameters, .htaccess files must not be used and the "AllowOverride" parameter must be set to "none".'
  desc 'check', '1. cd $DOMAIN_HOME/config/fmwconfig/components/OHS

2. find . -name .htaccess -print

3. If any .htaccess files are found, this is a finding.'
  desc 'fix', '1. cd $DOMAIN_HOME/config/fmwconfig/components/OHS

2. find . -name .htaccess -exec rm {} \\;'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65373r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64631'
  tag rid: 'SV-79121r1_rule'
  tag stig_id: 'OH12-1X-000196'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70561r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
