control 'SV-99885' do
  title 'Lighttpd must produce log records containing sufficient information to establish where within the web server the events occurred.'
  desc 'Ascertaining the correct location or process within the web server where the events occurred is important during forensic analysis. Correctly determining the web service, plug-in, or module will add information to the overall reconstruction of the logged event. For example, an event that occurred during communication to a cgi module might be handled differently than an event that occurred during a communication session to a user.

Without sufficient information establishing where the log event occurred within the web server, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

Lighttpd logs user activity in the access.log file using the Common Log Format (CLF). The CLF format, a World Wide Web Consortium standard, captures logs all user session information related to the hosted application session. This will enable forensic analysis of server events in case of malicious event.'
  desc 'check', 'At the command prompt, execute the following command:

tail -n 1 /opt/vmware/var/log/lighttpd/access.log

If any of the generated audit records are without sufficient information to establish where the event occurred, this is a finding.'
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the "lighttpd.conf" file with the following:

$HTTP["url"] !~ "(.css|.jpg|.gif|.png|.ico)$" {
  accesslog.filename = log_root + "/access.log"
}'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88927r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89235'
  tag rid: 'SV-99885r1_rule'
  tag stig_id: 'VRAU-LI-000060'
  tag gtitle: 'SRG-APP-000097-WSR-000058'
  tag fix_id: 'F-95977r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000132']
  tag nist: ['AU-3 c']
end
