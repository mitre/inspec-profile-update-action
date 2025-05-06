control 'SV-240220' do
  title 'Lighttpd must produce log records containing sufficient information to establish what type of events occurred.'
  desc 'Ascertaining the correct type of event that occurred is important during forensic analysis. The correct determination of the event and when it occurred is important in relation to other events that happened at that same time. 

Without sufficient information establishing what type of log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

Lighttpd logs user activity in the access.log file using the Common Log Format (CLF). The CLF format, a World Wide Web Consortium standard, captures logs all user session information related to the hosted application session. This will enable forensic analysis of server events in case of malicious event.'
  desc 'check', 'At the command prompt, execute the following command:

tail -n 4 /opt/vmware/var/log/lighttpd/access.log

If the GET or POST events do not exist in the access.log file, this is a finding.'
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the "lighttpd.conf" file with the following:

$HTTP["url"] !~ "(.css|.jpg|.gif|.png|.ico)$" {
  accesslog.filename = log_root + "/access.log"
}'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43453r667835_chk'
  tag severity: 'medium'
  tag gid: 'V-240220'
  tag rid: 'SV-240220r879563_rule'
  tag stig_id: 'VRAU-LI-000050'
  tag gtitle: 'SRG-APP-000095-WSR-000056'
  tag fix_id: 'F-43412r667836_fix'
  tag 'documentable'
  tag legacy: ['SV-99881', 'V-89231']
  tag cci: ['CCI-000130']
  tag nist: ['AU-3 a']
end
