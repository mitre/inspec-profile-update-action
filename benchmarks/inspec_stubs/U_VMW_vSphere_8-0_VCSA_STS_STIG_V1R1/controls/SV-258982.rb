control 'SV-258982' do
  title 'The vCenter STS service "ErrorReportValve showServerInfo" must be set to "false".'
  desc 'The Error Report Valve is a simple error handler for HTTP status codes that will generate and return HTML error pages. It can also be configured to return predefined static HTML pages for specific status codes and/or exception types. Disabling "showServerInfo" will only return the HTTP status code and remove all CSS from the default nonerror-related HTTP responses.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-sso/vmware-sts/conf/server.xml

Example result:

<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>

If the "ErrorReportValve" element is not defined or "showServerInfo" is not set to "false", this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-sso/vmware-sts/conf/server.xml

Locate the following Host block:

<Host ...>
...
</Host>

Inside this block, add or update the following on a new line:

<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>

Restart the service with the following command:

# vmon-cli --restart sts'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA Secure Token Service (STS)'
  tag check_id: 'C-62722r934602_chk'
  tag severity: 'medium'
  tag gid: 'V-258982'
  tag rid: 'SV-258982r934604_rule'
  tag stig_id: 'VCST-80-000067'
  tag gtitle: 'SRG-APP-000266-AS-000169'
  tag fix_id: 'F-62631r934603_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
