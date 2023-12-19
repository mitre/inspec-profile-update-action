control 'SV-240223' do
  title 'Lighttpd must produce log records containing sufficient information to establish the source of events.'
  desc 'Ascertaining the correct source, e.g. source IP, of the events is important during forensic analysis. Correctly determining the source will add information to the overall reconstruction of the logable event. By determining the source of the event correctly, analysis of the enterprise can be undertaken to determine if the event compromised other assets within the enterprise.

Without sufficient information establishing the source of the logged event, investigation into the cause of event is severely hindered. Log record content that may be necessary to satisfy the requirement of this control includes, but is not limited to, time stamps, source and destination IP addresses, user/process identifiers, event descriptions, application-specific events, success/fail indications, file names involved, access control, or flow control rules invoked.

Lighttpd logs user activity in the access.log file using the Common Log Format (CLF). The CLF format, a World Wide Web Consortium standard, captures logs all user session information related to the hosted application session. This will enable forensic analysis of server events in case of malicious event.'
  desc 'check', 'At the command prompt, execute the following command:

tail -n 4 /opt/vmware/var/log/lighttpd/access.log

If any of the generated audit records are without sufficient information to establish the source of the events, this is a finding.'
  desc 'fix', 'Navigate to and open /opt/vmware/etc/lighttpd/lighttpd.conf

Configure the "lighttpd.conf" file with the following:

$HTTP["url"] !~ "(.css|.jpg|.gif|.png|.ico)$" {
  accesslog.filename = log_root + "/access.log"
}'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x Lighttpd'
  tag check_id: 'C-43456r667844_chk'
  tag severity: 'medium'
  tag gid: 'V-240223'
  tag rid: 'SV-240223r879566_rule'
  tag stig_id: 'VRAU-LI-000065'
  tag gtitle: 'SRG-APP-000098-WSR-000059'
  tag fix_id: 'F-43415r667845_fix'
  tag 'documentable'
  tag legacy: ['SV-99887', 'V-89237']
  tag cci: ['CCI-000133']
  tag nist: ['AU-3 d']
end
