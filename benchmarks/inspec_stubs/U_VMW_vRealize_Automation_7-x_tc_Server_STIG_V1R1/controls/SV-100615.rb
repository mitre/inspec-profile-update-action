control 'SV-100615' do
  title 'tc Server VCO must produce log records that contain sufficient information to establish the outcome (success or failure) of events.'
  desc "After a security incident has occurred, investigators will often review log files to determine what happened. tc Server HORIZON must create a log entry when users access the system, and the system authenticates the users.

The logs must contain information about user sessions to include what type of event occurred, when (date and time) events occurred, where within the server the events occurred, the client source of the events, the outcome (success or failure) of the event, the identity of the user/subject/process associated with the event.

Like all web servers, tc Server generates HTTP status codes. The status code is a 3-digit indicator of the outcome of the server's response to the request."
  desc 'check', 'At the command prompt, execute the following command:

tail /storage/log/vmware/vco/app-server/localhost_access_log.txt

If the HTTP status codes are not being recorded, this is a finding.

Note: HTTP status codes are 3-digit codes, which are recorded immediately after "HTTP/1.1"'
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
  tag check_id: 'C-89657r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89965'
  tag rid: 'SV-100615r1_rule'
  tag stig_id: 'VRAU-TC-000225'
  tag gtitle: 'SRG-APP-000099-WSR-000061'
  tag fix_id: 'F-96707r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
