control 'SV-241677' do
  title 'tc Server CaSa must be configured with a cross-site scripting (XSS) filter.'
  desc 'Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be used by attackers to bypass access controls such as the same-origin policy.

As a web server, tc Server can be vulnerable to XSS if steps are not taken to mitigate the threat.  VMware provides the XssFilter component to provide a layer of defense against XSS. Filters are Java objects that performs filtering tasks on either the request to a resource (a servlet or static content), or on the response from a resource, or both.'
  desc 'check', 'At the command prompt, execute the following command:

grep -B 2 -A 7 XssFilter /usr/lib/vmware-casa/casa-webapp/webapps/admin/WEB-INF/web.xml

If the XSS filter is not present and there is no result returned, then this is a finding.'
  desc 'fix', 'Navigate to and open /usr/lib/vmware-casa/casa-webapp/webapps/admin/WEB-INF/web.xml.

Configure a <filter> node with the below configuration:

   <filter>
      <filter-name>xssfilter</filter-name>
      <filter-class>com.vmware.vcops.ui.util.XssFilter</filter-class>

      <init-param>
         <!-- Comma separated list of URLs that will be sanitized by this filter  -->
         <param-name>fileIncludes</param-name>
         <param-value>/vcops/services/api.js,/vcops/services/api-debug.js,/vcops/services/api-debug-doc.js</param-value>
      </init-param>
   </filter>
   <filter-mapping>
      <filter-name>xssfilter</filter-name>
      <url-pattern>/vcops/services/*</url-pattern>
   </filter-mapping>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44953r683891_chk'
  tag severity: 'medium'
  tag gid: 'V-241677'
  tag rid: 'SV-241677r879650_rule'
  tag stig_id: 'VROM-TC-000625'
  tag gtitle: 'SRG-APP-000246-WSR-000149'
  tag fix_id: 'F-44912r683892_fix'
  tag 'documentable'
  tag legacy: ['SV-99639', 'V-88989']
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
