control 'SV-99653' do
  title 'tc Server API must use the setCharacterEncodingFilter filter.'
  desc "Invalid user input occurs when a user inserts data or characters into a hosted application's data entry field and the hosted application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application compromise. Invalid user input is one of the primary methods employed when attempting to compromise an application. 

An attacker can also enter Unicode into hosted applications in an effort to break out of the document home or root home directory or to bypass security checks.

As a web server, tc Server can be vulnerable to character encoding attacks if steps are not taken to mitigate the threat.  VMware utilizes the standard Tomcat setCharacterEncodingFilter filter to provide a layer of defense against character encoding attacks. Filters are Java objects that performs filtering tasks on either the request to a resource (a servlet or static content), or on the response from a resource, or both."
  desc 'check', "Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/web.xml.

Verify that the 'setCharacterEncodingFilter' <filter> has been specified with the following command:

grep -B 2 -A 7 setCharacterEncodingFilter /usr/lib/vmware-vcops/tomcat-enterprise/conf/web.xml

If the “setCharacterEncodingFilter” filter has not been specified or is commented out, this is a finding."
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vcops/tomcat-enterprise/conf/web.xml.

Configure the <web-app> node with the <filter> node listed below.

            <filter>
                <filter-name>setCharacterEncodingFilter</filter-name>
                <filter-class>org.apache.catalina.filters.SetCharacterEncodingFilter</filter-class>
                <init-param>
                    <param-name>encoding</param-name>
                    <param-value>UTF-8</param-value>
                    <param-name>ignore</param-name>
                    <param-value>false</param-value>
                </init-param>
                <async-supported>true</async-supported>
            </filter>
           <filter-mapping>
             <filter-name>setCharacterEncodingFilter</filter-name>
             <url-pattern>/*</url-pattern>
          </filter-mapping>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88695r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89003'
  tag rid: 'SV-99653r1_rule'
  tag stig_id: 'VROM-TC-000660'
  tag gtitle: 'SRG-APP-000251-WSR-000157'
  tag fix_id: 'F-95745r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001310']
  tag nist: ['SI-10']
end
