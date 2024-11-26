control 'SV-99657' do
  title 'tc Server CaSa must set the welcome-file node to a default web page.'
  desc "The goal is to completely control the web user's experience in navigating any portion of the web document root directories. Ensuring all web content directories have at least the equivalent of an index.html file is a significant factor to accomplish this end.

Enumeration techniques, such as URL parameter manipulation, rely upon being able to obtain information about the web server's directory structure by locating directories without default pages. In the scenario, the web server will display to the user a listing of the files in the directory being accessed. By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version.

As a web server, tc Server can be vulnerable to enumeration techniques if steps are not taken to mitigate the vulnerability.  Ensuring that every document directory has an “index.jsp” (or equivalent) file is one common sense approach to mitigating the vulnerability."
  desc 'check', "At the command prompt, execute the following command:
 
grep -E -A 4 '<welcome-file-list' /usr/lib/vmware-casa/casa-webapp/conf/web.xml

If a <welcome-file> node is not set to a default web page, this is a finding."
  desc 'fix', 'Navigate to and open /usr/lib/vmware-casa/casa-webapp/conf/web.xml.

Inspect the file and ensure that it contains the below section:

    <welcome-file-list>
        <welcome-file>index.html</welcome-file>
        <welcome-file>index.htm</welcome-file>
        <welcome-file>index.jsp</welcome-file>
    </welcome-file-list>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88699r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89007'
  tag rid: 'SV-99657r1_rule'
  tag stig_id: 'VROM-TC-000670'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag fix_id: 'F-95749r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
