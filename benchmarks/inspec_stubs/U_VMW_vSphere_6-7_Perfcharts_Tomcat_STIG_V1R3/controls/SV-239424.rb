control 'SV-239424' do
  title 'Performance Charts must be configured to show error pages with minimal information.'
  desc 'Web servers will often display error messages to client users, including enough information to aid in the debugging of the error. The information given back in error messages may display the web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage. 

This information could be used by an attacker to blueprint what type of attacks might be successful. Therefore, Performance Charts must be configured with a catch-all error handler that redirects to a standard "error.jsp".'
  desc 'check', %q(At the command prompt, execute the following command:

#  xmllint --format /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml | sed '2 s/xmlns=".*"//g' | xmllint --xpath '/web-app/error-page/exception-type["text()=java.lang.Throwable"]/parent::error-page' -

Expected result:

<error-page>
    <exception-type>java.lang.Throwable</exception-type>
    <location>/http_error.jsp</location>
</error-page>

If the output does not match the expected result, this is a finding.)
  desc 'fix', 'Navigate to and open /usr/lib/vmware-perfcharts/tc-instance/webapps/statsreport/WEB-INF/web.xml.

Add the following section under the <web-apps> node:

<error-page>
    <exception-type>java.lang.Throwable</exception-type>
    <location>/error.jsp</location>
  </error-page>'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Perfcharts Tomcat'
  tag check_id: 'C-42657r816589_chk'
  tag severity: 'medium'
  tag gid: 'V-239424'
  tag rid: 'SV-239424r879655_rule'
  tag stig_id: 'VCPF-67-000023'
  tag gtitle: 'SRG-APP-000266-WSR-000159'
  tag fix_id: 'F-42616r674994_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
