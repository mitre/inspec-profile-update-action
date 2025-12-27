control 'SV-241599' do
  title 'tc Server UI must produce log records containing sufficient information to establish what type of events occurred.'
  desc 'After a security incident has occurred, investigators will often review log files to determine what happened. Understanding what type of event occurred is critical for investigation of a suspicious event.

Like all servers, tc Server will typically process “GET” and “POST” requests clients. These will help investigators understand what happened.'
  desc 'check', 'At the command prompt, execute the following command:

tail /storage/log/vcops/log/product-ui/localhost_access_log.YYYY-MM-dd.txt

Note: Substitute the actual date in the file name.

If HTTP "GET" and/or "POST" events are not being recorded, this is a finding.'
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
  tag check_id: 'C-44875r684117_chk'
  tag severity: 'medium'
  tag gid: 'V-241599'
  tag rid: 'SV-241599r879563_rule'
  tag stig_id: 'VROM-TC-000155'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag fix_id: 'F-44834r683658_fix'
  tag 'documentable'
  tag legacy: ['SV-99483', 'V-88833']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
