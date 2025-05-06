control 'SV-259115' do
  title 'The vCenter UI service "ErrorReportValve showServerInfo" must be set to "false".'
  desc 'The Error Report Valve is a simple error handler for HTTP status codes that will generate and return HTML error pages. It can also be configured to return predefined static HTML pages for specific status codes and/or exception types. Disabling "showServerInfo" will only return the HTTP status code and remove all CSS from the default nonerror-related HTTP responses.'
  desc 'check', %q(At the command prompt, run the following command:

# xmllint --xpath '/Server/Service/Engine/Host/Valve[@className="org.apache.catalina.valves.ErrorReportValve"]' /usr/lib/vmware-vsphere-ui/server/conf/server.xml

Example result:

<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>

If the "ErrorReportValve" element is not defined or "showServerInfo" is not set to "false", this is a finding.)
  desc 'fix', 'Navigate to and open:

/usr/lib/vmware-vsphere-ui/server/conf/server.xml

Locate the following Host block:

<Host ...>
...
</Host>

Inside this block, add or update the following on a new line:

<Valve className="org.apache.catalina.valves.ErrorReportValve" showServerInfo="false" showReport="false"/>

Restart the service with the following command:

# vmon-cli --restart vsphere-ui'
  impact 0.5
  ref 'DPMS Target VMware vSphere 8.0 VCSA User Interface (UI)'
  tag check_id: 'C-62855r935247_chk'
  tag severity: 'medium'
  tag gid: 'V-259115'
  tag rid: 'SV-259115r935249_rule'
  tag stig_id: 'VCUI-80-000067'
  tag gtitle: 'SRG-APP-000266-AS-000169'
  tag fix_id: 'F-62764r935248_fix'
  tag 'documentable'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
