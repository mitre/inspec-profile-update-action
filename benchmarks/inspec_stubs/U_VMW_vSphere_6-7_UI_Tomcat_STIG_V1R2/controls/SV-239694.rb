control 'SV-239694' do
  title 'vSphere UI must not have the Web Distributed Authoring (WebDAV) servlet installed.'
  desc 'WebDAV is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server and must therefore be disabled.

Tomcat uses the "org.apache.catalina.servlets.WebdavServlet" servlet to provide WebDAV services. Because the WebDAV service has been found to have an excessive number of vulnerabilities, this servlet must not be installed. vSphere UI does not configure WebDAV by default.'
  desc 'check', "At the command prompt, execute the following command: 

# grep -n 'webdav' /usr/lib/vmware-vsphere-ui/server/conf/web.xml

If the command produces any output, this is a finding."
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/web.xml.

Find the <servlet-name>webdav</servlet-name> node and remove the entire parent <servlet> block.

Find the <servlet-name>webdav</servlet-name> node and remove the entire parent <servlet-mapping> block.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 UI Tomcat'
  tag check_id: 'C-42927r679186_chk'
  tag severity: 'medium'
  tag gid: 'V-239694'
  tag rid: 'SV-239694r679188_rule'
  tag stig_id: 'VCUI-67-000013'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag fix_id: 'F-42886r679187_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
