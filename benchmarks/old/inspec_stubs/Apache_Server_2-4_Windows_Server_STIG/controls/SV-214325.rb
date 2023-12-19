control 'SV-214325' do
  title 'The Apache web server must have Web Distributed Authoring (WebDAV) disabled.'
  desc 'A web server can be installed with functionality that, just by its nature, is not secure. WebDAV is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.'
  desc 'check', %q(In a command line, navigate to "<'INSTALLED PATH'>\bin". Run "httpd -M" to view a list of installed modules.

If any of the following modules are present, this is a finding:

dav_module
dav_fs_module
dav_lock_module)
  desc 'fix', "Edit the <'INSTALL PATH'>\\conf\\httpd.conf file and remove the following modules:

dav_module
dav_fs_module
dav_lock_module

Restart the Apache service."
  impact 0.5
  ref 'DPMS Target Apache Server 2.4 Windows Server'
  tag check_id: 'C-15537r277478_chk'
  tag severity: 'medium'
  tag gid: 'V-214325'
  tag rid: 'SV-214325r879587_rule'
  tag stig_id: 'AS24-W1-000330'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag fix_id: 'F-15535r277479_fix'
  tag 'documentable'
  tag legacy: ['SV-102475', 'V-92387']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
