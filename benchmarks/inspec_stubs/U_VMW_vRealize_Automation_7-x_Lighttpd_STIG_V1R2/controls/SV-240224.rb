control 'SV-240224' do
  title 'Lighttpd must produce log records containing sufficient information to establish the outcome (success or failure) of events.'
  desc 'Ascertaining the success or failure of an event is important during forensic analysis. Correctly determining the outcome will add information to the overall reconstruction of the logable event. By determining the success or failure of the event correctly, analysis of the enterprise can be undertaken to determine if events tied to the event occurred in other areas within the enterprise.

Without sufficient information establishing the success or failure of the logged event, investigation into the cause of event is severely hindered. The success or failure also provides a means to measure the impact of an event and help authorized personnel to determine the appropriate response. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

Lighttpd logs user activity in the access.log file using the Common Log Format (CLF). The CLF format, a World Wide Web Consortium standard, captures logs all user session information related to the hosted application session. This will enable forensic analysis of server events in case of malicious event.'
  desc 'check', 'At the command prompt, execute the following command:

Note: The HTTP status code indicating success or failure is a 3-digit integer immediately after "HTTP/1.1". Any value other than a 3-digit code immediately following "HTTP/1.1" is a failure of the logging process.

tail -n 4 /opt/vmware/var/log/lighttpd/access.log

If any of the generated audit records are without sufficient information to establish the outcome of the event (success or failure), this is a finding.'
  desc 'fix', 'Navigate to and open the /opt/vmware/etc/lighttpd/lighttpd.conf file

Configure the "lighttpd.conf" file with the following:

$HTTP["url"] !~ "(.css|.jpg|.gif|.png|.ico)$" {
  accesslog.filename = log_root + "/access.log"
}'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43457r668003_chk'
  tag severity: 'medium'
  tag gid: 'V-240224'
  tag rid: 'SV-240224r879567_rule'
  tag stig_id: 'VRAU-LI-000075'
  tag gtitle: 'SRG-APP-000099-WSR-000061'
  tag fix_id: 'F-43416r667848_fix'
  tag 'documentable'
  tag legacy: ['SV-99889', 'V-89239']
  tag cci: ['CCI-000134']
  tag nist: ['AU-3 e']
end
