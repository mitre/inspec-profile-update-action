control 'SV-239701' do
  title 'vSphere UI must set the welcome-file node to a default web page.'
  desc %q(Enumeration techniques, such as URL parameter manipulation, rely on being able to obtain information about the web server's directory structure by locating directories without default pages. In this scenario, the web server will display to the user a listing of the files in the directory being accessed. 

By having a default hosted application web page, the anonymous web user will not obtain directory browsing information or an error message that reveals the server type and version. Ensuring that every document directory has an "index.jsp" (or equivalent) file is one approach to mitigating the vulnerability.)
  desc 'check', %q(At the command prompt, execute the following command:
 
# xmllint --format /usr/lib/vmware-vsphere-ui/server/conf/web.xml | sed 's/xmlns=".*"//g' | xmllint --xpath '/web-app/welcome-file-list' -

Expected result:

<welcome-file-list>

    <welcome-file>index.html</welcome-file>

    <welcome-file>index.htm</welcome-file>

    <welcome-file>index.jsp</welcome-file>

  </welcome-file-list>

If the output of the command does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vsphere-ui/server/conf/web.xml.

Add the following section under the <web-apps> node:

    <welcome-file-list>
        <welcome-file>index.html</welcome-file>
        <welcome-file>index.htm</welcome-file>
        <welcome-file>index.jsp</welcome-file>
    </welcome-file-list>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 UI Tomcat'
  tag check_id: 'C-42934r679207_chk'
  tag severity: 'medium'
  tag gid: 'V-239701'
  tag rid: 'SV-239701r879655_rule'
  tag stig_id: 'VCUI-67-000020'
  tag gtitle: 'SRG-APP-000266-WSR-000142'
  tag fix_id: 'F-42893r679208_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
