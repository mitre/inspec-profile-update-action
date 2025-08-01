control 'SV-240757' do
  title 'tc Server VCAC must produce log records containing sufficient information to establish where within the web server the events occurred.'
  desc 'After a security incident has occurred, investigators will often review log files to determine what happened. tc Server HORIZON must create a log entry when users access the system, and the system authenticates the users.

The logs must contain information about user sessions to include what type of event occurred, when (date and time) events occurred, where within the server the events occurred, the client source of the events, the outcome (success or failure) of the event, the identity of the user/subject/process associated with the event.

Like all web servers, tc Server will log the requested URL and the parameters, if any, sent in the request. This information will enable investigators to determine where in the server an action was requested.'
  desc 'check', 'At the command prompt, execute the following command:

tail /storage/log/vmware/vcac/access_log.YYYY-MM-dd.txt

Note: Substitute the actual date in the file name.

If the location of events are not being recorded, this is a finding.'
  desc 'fix', 'Navigate to and open /etc/vcac/server.xml.

Navigate to and locate <Host>.

Configure the <Host> node with the <AccessLogValve> below.

Note: The "AccessLogValve" should be configured as follows:
               <Valve className="org.apache.catalina.valves.AccessLogValve"
                      checkExists="true" 
                      directory="logs"
                      pattern="%h %l %u %t &quot;%r&quot; %s %b"
                      prefix="access_log"
                      requestAttributesEnabled="true"
                      rotatable="false"
                      suffix=".txt"/>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-43990r674013_chk'
  tag severity: 'medium'
  tag gid: 'V-240757'
  tag rid: 'SV-240757r879565_rule'
  tag stig_id: 'VRAU-TC-000185'
  tag gtitle: 'SRG-APP-000097-WSR-000058'
  tag fix_id: 'F-43949r674014_fix'
  tag 'documentable'
  tag legacy: ['SV-100599', 'V-89949']
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
