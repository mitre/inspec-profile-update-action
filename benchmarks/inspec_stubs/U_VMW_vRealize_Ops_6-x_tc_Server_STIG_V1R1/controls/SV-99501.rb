control 'SV-99501' do
  title 'tc Server UI must produce log records containing sufficient information to establish the source of events.'
  desc 'After a security incident has occurred, investigators will often review log files to determine what happened. tc Server HORIZON must create a log entry when a user accesses the system and the system authenticates users.

The logs must contain information about user sessions to include what type of event occurred, when (date and time) events occurred, where within the server the events occurred, the client source of the events, the outcome (success or failure) of the event, the identity of the user/subject/process associated with the event.

As a Tomcat derivative, tc Server can be configured with an “AccessLogValve”. A Valve element represents a component that can be inserted into the request processing pipeline.  The pattern attribute of the “AccessLogValve” controls which data gets logged. The “%h” parameter will record the remote hostname or IP address that sent the request; i.e. the source of the event.'
  desc 'check', 'At the command prompt, execute the following command:

grep -v 127.0 /storage/log/vcops/log/product-ui/localhost_access_log.YYYY-MM-dd.txt

Note: Substitute the actual date in the file name.

If the source IP of events are not being recorded, this is a finding.'
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
  ref 'DPMS Target VMware vRealize Operations Manager 6.x tcServer'
  tag check_id: 'C-88543r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88851'
  tag rid: 'SV-99501r1_rule'
  tag stig_id: 'VROM-TC-000200'
  tag gtitle: 'SRG-APP-000098-WSR-000059'
  tag fix_id: 'F-95593r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
