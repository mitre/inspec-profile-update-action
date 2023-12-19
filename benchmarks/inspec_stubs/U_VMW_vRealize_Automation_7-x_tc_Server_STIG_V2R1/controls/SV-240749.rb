control 'SV-240749' do
  title 'tc Server HORIZON must produce log records containing sufficient information to establish what type of events occurred.'
  desc 'After a security incident has occurred, investigators will often review log files to determine what happened. Understanding what type of event occurred is critical for investigation of a suspicious event.

Like all servers, tc Server will typically process GET and POST requests clients. These will help investigators understand what happened.'
  desc 'check', 'At the command prompt, execute the following command:

tail /storage/log/vmware/horizon/localhost_access_log.YYYY-MM-dd.txt

Note: Substitute the actual date in the file name.

If HTTP "GET" and/or "POST" events are not being recorded, this is a finding.'
  desc 'fix', 'Navigate to and open /opt/vmware/horizon/workspace/conf/server.xml.

Navigate to and locate <Host>.

Configure the <Host> node with the <AccessLogValve> below.

Note: The "AccessLogValve" should be configured as follows:
                <Valve className="org.apache.catalina.valves.AccessLogValve"
                       directory="logs"
                       pattern="%h %l %u %t &quot;%r&quot; %s %b"
                       prefix="localhost_access_log."
                       suffix=".txt"/>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-43982r673989_chk'
  tag severity: 'medium'
  tag gid: 'V-240749'
  tag rid: 'SV-240749r673991_rule'
  tag stig_id: 'VRAU-TC-000145'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag fix_id: 'F-43941r673990_fix'
  tag 'documentable'
  tag legacy: ['SV-100583', 'V-89933']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
