control 'SV-241615' do
  title 'tc Server CaSa must produce log records that contain sufficient information to establish the outcome (success or failure) of events.'
  desc "After a security incident has occurred, investigators will often review log files to determine what happened. tc Server HORIZON must create a log entry when a user accesses the system and the system authenticates users.

The logs must contain information about user sessions to include what type of event occurred, when (date and time) events occurred, where within the server the events occurred, the client source of the events, the outcome (success or failure) of the event, the identity of the user/subject/process associated with the event.

Like all web servers, tc Server generates HTTP status codes. The status code is a three-digit indicator of the outcome of the server's response to the request."
  desc 'check', 'At the command prompt, execute the following command:

tail /storage/log/vcops/log/casa/localhost_access_log.YYYY-MM-dd.txt

Note: Substitute the actual date in the file name.

If the HTTP status codes are not being recorded, this is a finding.

Note: HTTP status codes are 3-digit codes, which are recorded immediately after "HTTP/1.1"'
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
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44891r684135_chk'
  tag severity: 'medium'
  tag gid: 'V-241615'
  tag rid: 'SV-241615r879567_rule'
  tag stig_id: 'VROM-TC-000235'
  tag gtitle: 'SRG-APP-000099-WSR-000061'
  tag fix_id: 'F-44850r683706_fix'
  tag 'documentable'
  tag legacy: ['SV-99515', 'V-88865']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
