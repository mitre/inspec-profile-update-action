control 'SV-99883' do
  title 'Lighttpd must produce log records containing sufficient information to establish when (date and time) events occurred.'
  desc 'Ascertaining the correct order of the events that occurred is important during forensic analysis. Events that appear harmless by themselves might be flagged as a potential threat when properly viewed in sequence. By also establishing the event date and time, an event can be properly viewed with an enterprise tool to fully see a possible threat in its entirety.

Without sufficient information establishing when the log event occurred, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

Lighttpd logs user activity in the access.log file using the Common Log Format (CLF). The CLF format, a World Wide Web Consortium standard, captures logs all user session information related to the hosted application session. This will enable forensic analysis of server events in case of malicious event.'
  desc 'check', 'At the command prompt, execute the following command:

tail -n 1 /opt/vmware/var/log/lighttpd/access.log

If the generated log records do not have date and time data, this is a finding.'
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the "lighttpd.conf" file with the following:

$HTTP["url"] !~ "(.css|.jpg|.gif|.png|.ico)$" {
  accesslog.filename = log_root + "/access.log"
}'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x Lighttpd'
  tag check_id: 'C-88925r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89233'
  tag rid: 'SV-99883r1_rule'
  tag stig_id: 'VRAU-LI-000055'
  tag gtitle: 'SRG-APP-000096-WSR-000057'
  tag fix_id: 'F-95975r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000131']
  tag nist: ['AU-3 b']
end
