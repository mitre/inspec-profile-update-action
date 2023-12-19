control 'SV-240243' do
  title 'Lighttpd must not have the Web Distributed Authoring (WebDAV) module installed.'
  desc 'A web server can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.

Lighttpd uses the mod_webdav module to provide WebDAV services. This module must not be installed.'
  desc 'check', %q(At the command prompt, execute the following command:    

cat /opt/vmware/etc/lighttpd/lighttpd.conf | awk '/server\.modules/,/\\)/'

If the value "mod_webdav" module is listed, this is a finding.)
  desc 'fix', 'Navigate to and open the /opt/vmware/etc/lighttpd/lighttpd.conf file

Navigate to the server.modules section.

In the server.modules section, delete the  "mod_webdav" entry.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43476r667904_chk'
  tag severity: 'medium'
  tag gid: 'V-240243'
  tag rid: 'SV-240243r879587_rule'
  tag stig_id: 'VRAU-LI-000200'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag fix_id: 'F-43435r667905_fix'
  tag 'documentable'
  tag legacy: ['SV-99917', 'V-89267']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
