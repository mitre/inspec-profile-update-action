control 'SV-241642' do
  title 'tc Server CaSa must have mappings set for Java Servlet Pages.'
  desc 'Resource mapping is the process of tying a particular file type to a process in the web server that can serve that type of file to a requesting client and to identify which file types are not to be delivered to a client.

By not specifying which files can and which files cannot be served to a user, the web server could deliver to a user web server configuration files, log files, password files, etc.

As a derivative of the Apache Tomcat project, tc Server is a java-based web server.  As a result, the main file extension used by tc Server is “*.jsp”. This check ensures that the “*.jsp” file type has been properly mapped to servlets.'
  desc 'check', "At the command prompt, execute the following command: 

grep -E '<url-pattern>\\*\\.jsp</url-pattern>' -B 2 -A 2 /usr/lib/vmware-casa/casa-webapp/conf/web.xml

If the “jsp” and “jspx” file extensions have not been mapped to the JSP servlet, this is a finding."
  desc 'fix', 'Navigate to and open /usr/lib/vmware-casa/casa-webapp/conf/web.xml.

Navigate to and locate the mapping for the JSP servlet. It is the <servlet-mapping> node that contains <servlet-name>jsp</servlet-name>.

Configure the <servlet-mapping> node to look like the code snippet below:

    <!-- The mappings for the JSP servlet -->
    <servlet-mapping>
        <servlet-name>jsp</servlet-name>
        <url-pattern>*.jsp</url-pattern>
        <url-pattern>*.jspx</url-pattern>
    </servlet-mapping>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44918r684155_chk'
  tag severity: 'medium'
  tag gid: 'V-241642'
  tag rid: 'SV-241642r879587_rule'
  tag stig_id: 'VROM-TC-000385'
  tag gtitle: 'SRG-APP-000141-WSR-000083'
  tag fix_id: 'F-44877r683787_fix'
  tag 'documentable'
  tag legacy: ['SV-99569', 'V-88919']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
