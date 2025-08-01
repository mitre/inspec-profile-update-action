control 'SV-100585' do
  title 'tc Server VCO must produce log records containing sufficient information to establish what type of events occurred.'
  desc 'After a security incident has occurred, investigators will often review log files to determine what happened. Understanding what type of event occurred is critical for investigation of a suspicious event.

Like all servers, tc Server will typically process GET and POST requests clients. These will help investigators understand what happened.'
  desc 'check', 'At the command prompt, execute the following command:

tail /storage/log/vmware/vco/app-server/localhost_access_log.txt

If HTTP "GET" and/or "POST" events are not being recorded, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/vco/app-server/server.xml.

Navigate to and locate <Host>.

Configure the <Host> node with the <AccessLogValve> below.

Note: The "AccessLogValve" should be configured as follows:
                <Valve className="org.apache.catalina.valves.AccessLogValve"
                       directory="logs"
                       pattern="%h %l %u %t &quot;%r&quot; %s %b"
                       prefix="localhost_access_log."
                       suffix=".txt"/>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x tcServer'
  tag check_id: 'C-89627r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89935'
  tag rid: 'SV-100585r1_rule'
  tag stig_id: 'VRAU-TC-000150'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag fix_id: 'F-96677r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
