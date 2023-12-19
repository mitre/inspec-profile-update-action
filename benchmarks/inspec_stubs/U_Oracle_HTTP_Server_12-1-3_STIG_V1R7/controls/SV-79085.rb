control 'SV-79085' do
  title 'OHS must have Entity tags (ETags) disabled.'
  desc 'Entity tags (ETags) are used for cache management to save network bandwidth by not sending a web page to the requesting client if the cached version on the client is current.  When the client only has the ETag information, the client will make a request to the server with the ETag.  The server will then determine if the client can use the client cached version of the web page or if a new version is required.

As part of the ETag information, the server sends to the client the index node (inode) information for the file being requested.  The inode information gives an attacker sensitive information like inode number, multipart MIME boundaries and makes certain NFS attacks much simpler to execute.'
  desc 'check', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "Header" and "FileETag" directives at the OHS server, virtual host, or directory configuration scope.

3. If the "Header" and "FileETag" directives are omitted or set improperly, this is a finding.'
  desc 'fix', '1. Open $DOMAIN_HOME/config/fmwconfig/components/OHS/<componentName>/httpd.conf and every .conf file (e.g., ssl.conf) included in it with an editor.

2. Search for the "Header" and "FileETag" directives at the OHS server, virtual host, or directory configuration scopes.

3a. Set the "Header" directive to "unset ETag", add the directive if it does not exist.
3b. Set the "FileETag" directive to "none", add the directive if it does not exist.'
  impact 0.5
  ref 'DPMS Target Oracle HTTP Server (OHS) 12.1.x'
  tag check_id: 'C-65337r1_chk'
  tag severity: 'medium'
  tag gid: 'V-64595'
  tag rid: 'SV-79085r1_rule'
  tag stig_id: 'OH12-1X-000178'
  tag gtitle: 'SRG-APP-000516-WSR-000174'
  tag fix_id: 'F-70525r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
