control 'SV-240794' do
  title 'tc Server ALL must not have the Web Distributed Authoring (WebDAV) servlet installed.'
  desc 'A web server can be installed with functionality that, just by its nature, is not secure. Web Distributed Authoring (WebDAV) is an extension to the HTTP protocol that, when developed, was meant to allow users to create, change, and move documents on a server, typically a web server or web share. Allowing this functionality, development, and deployment is much easier for web authors.

WebDAV is not widely used and has serious security concerns because it may allow clients to modify unauthorized files on the web server.

As an extension to Tomcat, tc Server VCO-CFG uses the org.apache.catalina.servlets.WebdavServlet servlet to provide WebDAV services. Because the WebDAV service has been found to have an excessive number of vulnerabilities, this servlet must not be installed.'
  desc 'check', "At the command prompt, execute the following command: 

find / -name 'web.xml' -print0 | xargs -0r grep -HEn 'webdav'

If the command produces any output, this is a finding."
  desc 'fix', 'Navigate to and open all listed files.

Navigate to and locate the mapping for the JSP servlet. It is the <servlet-mapping> node that contains <servlet-name>webdav</servlet-name>.

Remove the WebDAV servlet and any mapping associated with it.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44027r674124_chk'
  tag severity: 'medium'
  tag gid: 'V-240794'
  tag rid: 'SV-240794r674126_rule'
  tag stig_id: 'VRAU-TC-000385'
  tag gtitle: 'SRG-APP-000141-WSR-000085'
  tag fix_id: 'F-43986r674125_fix'
  tag 'documentable'
  tag legacy: ['SV-100671', 'V-90021']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
