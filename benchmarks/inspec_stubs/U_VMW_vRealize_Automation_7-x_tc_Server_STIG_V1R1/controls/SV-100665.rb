control 'SV-100665' do
  title 'tc Server HORIZON must have mappings set for Java Servlet Pages.'
  desc 'Resource mapping is the process of tying a particular file type to a process in the web server that can serve that type of file to a requesting client and to identify which file types are not to be delivered to a client.

By not specifying which files can and which files cannot be served to a user, the web server could deliver to a user web server configuration files, log files, password files, etc. 

As a derivative of the Apache Tomcat project, tc Server is a java-based web server. As a result, the main file extension used by tc Server is *.jsp. This check ensures that the *.jsp file type has been properly mapped to servlets.'
  desc 'check', "At the command prompt, execute the following command: 

 grep -E '<url-pattern>\\*\\.jsp</url-pattern>'  -B 2 -A 2 /opt/vmware/horizon/workspace/conf/web.xml

If the jsp and jspx file extensions have not been mapped to the JSP servlet, this is a finding."
  desc 'fix', 'Navigate to and open /opt/vmware/horizon/workspace/conf/web.xml.

Navigate to and locate the mapping for the JSP servlet. It is the  <servlet-mapping> node that contains <servlet-name>jsp</servlet-name>.

Configure the <servlet-mapping> node to look like the code snippet below:

    <!-- The mappings for the JSP servlet -->
    <servlet-mapping>
        <servlet-name>jsp</servlet-name>
        <url-pattern>*.jsp</url-pattern>
        <url-pattern>*.jspx</url-pattern>
    </servlet-mapping>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89707r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90015'
  tag rid: 'SV-100665r1_rule'
  tag stig_id: 'VRAU-TC-000370'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag fix_id: 'F-96757r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
