control 'SV-221414' do
  title 'Users and scripts running on behalf of users must be contained to the document root or home directory tree of OHS.'
  desc "A web server is designed to deliver content and execute scripts or applications on the request of a client or user.  Containing user requests to files in the directory tree of the hosted web application and limiting the execution of scripts and applications guarantees that the user is not accessing information protected outside the application's realm.  

The web server must also prohibit users from jumping outside the hosted application directory tree through access to the user's home directory, symbolic links or shortcuts, or through search paths for missing files."
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "<Directory>" directive at OHS server and virtual host configuration scopes.

3. If the "Options" directive within the "<Directory>" directive is omitted or is set improperly, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "<Directory>" directive at OHS server and virtual host configuration scopes.

3. Set the "Options" directive within the "<Directory>" directive to "None", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23129r414925_chk'
  tag severity: 'medium'
  tag gid: 'V-221414'
  tag rid: 'SV-221414r879587_rule'
  tag stig_id: 'OH12-1X-000172'
  tag gtitle: 'SRG-APP-000141-WSR-000087'
  tag fix_id: 'F-23118r414926_fix'
  tag 'documentable'
  tag legacy: ['SV-78893', 'V-64403']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
