control 'SV-221413' do
  title 'OHS must have resource mappings set to disable the serving of certain file types.'
  desc 'Resource mapping is the process of tying a particular file type to a process in the web server that can serve that type of file to a requesting client and to identify which file types are not to be delivered to a client.

By not specifying which files can and which files cannot be served to a user, the web server could deliver to a user web server configuration files, log files, password files, etc. 

The web server must only allow hosted application file types to be served to a user and all other types must be disabled.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for "<FilesMatch>" directives beyond the "<FilesMatch"^\\.ht">" directive at the OHS server, virtual host, and directory configuration scopes.

3. If the "<FilesMatch>" directive is omitted or it and/or any directives it contains are set improperly, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for "<FilesMatch>" directives beyond the "<FilesMatch"^\\.ht">" directive at the OHS server, virtual host, and directory configuration scopes.

3. Set the "<FilesMatch>" directive to ""^(?!.*\\.(gif|jpe?g|png|html?|js|css)).*$"" or other value appropriate for the server/site to prevent inappropriate file access, add the directive if it does not exist.

4a. Within the "<FilesMatch "^(?!.*\\.(gif|jpe?g|png|html?|js|css)).*$">" directive, set the "Order" directive to "allow,deny", add the directive if it does not exist.
4b. Within the "<FilesMatch "^(?!.*\\.(gif|jpe?g|png|html?|js|css)).*$">" directive, set the "Deny" directive to "from all", add the directive if it does not exist.
4c. Within the "<FilesMatch "^(?!.*\\.(gif|jpe?g|png|html?|js|css)).*$">" directive, set the "Satisfy" directive to "All", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server 12.1.3'
  tag check_id: 'C-23128r414922_chk'
  tag severity: 'medium'
  tag gid: 'V-221413'
  tag rid: 'SV-221413r879587_rule'
  tag stig_id: 'OH12-1X-000169'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag fix_id: 'F-23117r414923_fix'
  tag 'documentable'
  tag legacy: ['SV-78891', 'V-64401']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
