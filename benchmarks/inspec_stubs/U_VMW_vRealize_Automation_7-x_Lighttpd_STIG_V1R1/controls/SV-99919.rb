control 'SV-99919' do
  title 'Lighttpd must not have the webdav configuration file included.'
  desc "A web server can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.

The Lighttpd configuration file uses the 'include' statement to include other configuration files. The default lighttpd.conf file contains a reference to include a webdav.conf file, and it is possible for the WebDAV module to be loaded in other files."
  desc 'check', "At the command prompt, execute the following command:

grep 'webdav.conf' /opt/vmware/etc/lighttpd/lighttpd.conf

If the return value is an include statement and it is not commented out, this is a finding."
  desc 'fix', 'Navigate to and open  /opt/vmware/etc/lighttpd/lighttpd.conf

Delete or comment out the include "conf.d/webdav.conf" statement.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88961r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89269'
  tag rid: 'SV-99919r1_rule'
  tag stig_id: 'VRAU-LI-000205'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag fix_id: 'F-96011r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
