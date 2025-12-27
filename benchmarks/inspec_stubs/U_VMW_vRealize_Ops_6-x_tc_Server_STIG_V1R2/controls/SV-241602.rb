control 'SV-241602' do
  title 'tc Server UI must produce log records containing sufficient information to establish when (date and time) events occurred.'
  desc 'After a security incident has occurred, investigators will often review log files to determine when events occurred. Understanding the precise sequence of events is critical for investigation of a suspicious event.

As a Tomcat derivative, tc Server can be configured with an “AccessLogValve. A Valve element represents a component that can be inserted into the request processing pipeline.  The pattern attribute of the “AccessLogValve” controls which data gets logged. The “%t” parameter specifies that the system time should be recorded.'
  desc 'check', 'At the command prompt, execute the following command:

tail /storage/log/vcops/log/product-ui/localhost_access_log.YYYY-MM-dd.txt

Note: Substitute the actual date in the file name.

If the time and date of events are not being recorded, this is a finding.'
  desc 'fix', 'Navigate to and open /usr/lib/vmware-vcops/tomcat-web-app/conf/server.xml.

Navigate to and locate <Host>.

Configure the <Host> node with the <AccessLogValve> below.

Note: The “AccessLogValve” should be configured as follows: 

                <Valve className="org.apache.catalina.valves.AccessLogValve"
                       directory="logs"
                       pattern="%h %l %u %t &quot;%r&quot; %s %b"
                       prefix="localhost_access_log."
                       suffix=".txt"/>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44878r684121_chk'
  tag severity: 'medium'
  tag gid: 'V-241602'
  tag rid: 'SV-241602r879564_rule'
  tag stig_id: 'VROM-TC-000170'
  tag gtitle: 'SRG-APP-000096-WSR-000057'
  tag fix_id: 'F-44837r683667_fix'
  tag 'documentable'
  tag legacy: ['SV-99489', 'V-88839']
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
