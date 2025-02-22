control 'SV-100893' do
  title 'The vAMI sfcb config file must be group-owned by root.'
  desc 'Log records can be generated from various components within the application server. The list of logged events is the set of events for which logs are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating log records (i.e., logable events). Application server log events may include, but are not limited to, HTTP, Database, and XML parsing activity. The application server must be capable of allowing defined individuals or roles to change the logging to be performed on all application server components, based on all selectable event criteria during a defined time threshold. The time threshold can be defined by such events as a change in the threat environment. The ability to change logging parameters during the threat would allow important forensic information to be gathered during the time duration of the threat.'
  desc 'check', 'At the command prompt, execute the following command:

ls -lL /opt/vmware/etc/sfcb/sfcb.cfg

If the sfcb.cfg file is not group-owned by root, this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chown root:root /opt/vmware/etc/sfcb/sfcb.cfg'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89935r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90243'
  tag rid: 'SV-100893r1_rule'
  tag stig_id: 'VRAU-VA-000405'
  tag gtitle: 'SRG-APP-000353-AS-000235'
  tag fix_id: 'F-96985r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001914']
  tag nist: ['AU-12 (3)']
end
