control 'SV-99521' do
  title 'tc Server CaSa must produce log records containing sufficient information to establish the identity of any user/subject or process associated with an event.'
  desc 'After a security incident has occurred, investigators will often review log files to determine what happened. tc Server HORIZON must create a log entry when a user accesses the system and the system authenticates users.

The logs must contain information about user sessions to include what type of event occurred, when (date and time) events occurred, where within the server the events occurred, the client source of the events, the outcome (success or failure) of the event, the identity of the user/subject/process associated with the event.

As a Tomcat derivative, tc Server can be configured with an “AccessLogValve”. A Valve element represents a component that can be inserted into the request processing pipeline.  The pattern attribute of the “AccessLogValve” controls which data gets logged. The “%u” parameter will record the remote user that was authenticated.  Knowing the authenticated user could be crucial to know in an investigation.'
  desc 'check', 'At the command prompt, execute the following command:

tail /storage/log/vcops/log/casa/localhost_access_log.YYYY-MM-dd.txt

Note: Substitute the actual date in the file name.

If the identity of the user is not being recorded, this is a finding.'
  desc 'fix', 'Navigate to and open /usr/lib/vmware-casa/casa-webapp/conf/server.xml.

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
  tag check_id: 'C-88563r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88871'
  tag rid: 'SV-99521r1_rule'
  tag stig_id: 'VROM-TC-000250'
  tag gtitle: 'SRG-APP-000100-WSR-000064'
  tag fix_id: 'F-95613r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001487']
  tag nist: ['AU-3 f']
end
