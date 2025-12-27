control 'SV-100597' do
  title 'tc Server VCO must produce log records containing sufficient information to establish where within the web server the events occurred.'
  desc 'After a security incident has occurred, investigators will often review log files to determine what happened. tc Server HORIZON must create a log entry when users access the system, and the system authenticates the users.

The logs must contain information about user sessions to include what type of event occurred, when (date and time) events occurred, where within the server the events occurred, the client source of the events, the outcome (success or failure) of the event, the identity of the user/subject/process associated with the event.

Like all web servers, tc Server will log the requested URL and the parameters, if any, sent in the request. This information will enable investigators to determine where in the server an action was requested.'
  desc 'check', 'At the command prompt, execute the following command:

tail /storage/log/vmware/vco/app-server/localhost_access_log.txt

If the location of events are not being recorded, this is a finding.'
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
  tag check_id: 'C-89639r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89947'
  tag rid: 'SV-100597r1_rule'
  tag stig_id: 'VRAU-TC-000180'
  tag gtitle: 'SRG-APP-000097-WSR-000058'
  tag fix_id: 'F-96689r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
