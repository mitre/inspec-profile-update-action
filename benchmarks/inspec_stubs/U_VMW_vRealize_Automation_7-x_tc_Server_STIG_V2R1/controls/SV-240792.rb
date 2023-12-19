control 'SV-240792' do
  title 'tc Server VCO must have mappings set for Java Servlet Pages.'
  desc 'Resource mapping is the process of tying a particular file type to a process in the web server that can serve that type of file to a requesting client and to identify which file types are not to be delivered to a client.

By not specifying which files can and which files cannot be served to a user, the web server could deliver to a user web server configuration files, log files, password files, etc. 

As a derivative of the Apache Tomcat project, tc Server is a java-based web server. As a result, the main file extension used by tc Server is *.jsp. This check ensures that the *.jsp file type has been properly mapped to servlets.'
  desc 'check', "At the command prompt, execute the following command: 

 grep -E '<url-pattern>\\*\\.jsp</url-pattern>'  -B 2 -A 2 /etc/vco/app-server/web.xml

If the jsp and jspx file extensions have not been mapped to the JSP servlet, this is a finding."
  desc 'fix', 'Navigate to and open /etc/vco/app-server/web.xml.

Navigate to and locate the mapping for the JSP servlet. It is the  <servlet-mapping> node that contains <servlet-name>jsp</servlet-name>.

Configure the <servlet-mapping> node to look like the code snippet below:

    <!-- The mappings for the JSP servlet -->
    <servlet-mapping>
        <servlet-name>jsp</servlet-name>
        <url-pattern>*.jsp</url-pattern>
        <url-pattern>*.jspx</url-pattern>
    </servlet-mapping>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44025r674118_chk'
  tag severity: 'medium'
  tag gid: 'V-240792'
  tag rid: 'SV-240792r674120_rule'
  tag stig_id: 'VRAU-TC-000375'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag fix_id: 'F-43984r674119_fix'
  tag 'documentable'
  tag legacy: ['SV-100667', 'V-90017']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
