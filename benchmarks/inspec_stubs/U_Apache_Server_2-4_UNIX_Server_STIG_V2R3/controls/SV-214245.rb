control 'SV-214245' do
  title 'The Apache web server must have Web Distributed Authoring (WebDAV) disabled.'
  desc 'A web server can be installed with functionality that, by its nature, is not secure. WebDAV is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.'
  desc 'check', 'In a command line, run "httpd -M | sort" to view a list of installed modules.

If any of the following modules are present, this is a finding:

dav_module
dav_fs_module
dav_lock_module'
  desc 'fix', %q(Determine where the "dav" modules are located by running the following command:

grep -rl "dav_module" <'INSTALL PATH'>

Edit the file and comment out the following modules:

dav_module
dav_fs_module
dav_lock_module

Restart Apache: apachectl restart)
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 UNIX Server'
  tag check_id: 'C-15459r276995_chk'
  tag severity: 'medium'
  tag gid: 'V-214245'
  tag rid: 'SV-214245r612240_rule'
  tag stig_id: 'AS24-U1-000330'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag fix_id: 'F-15457r276996_fix'
  tag 'documentable'
  tag legacy: ['SV-102747', 'V-92659']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
