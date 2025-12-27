control 'SV-100849' do
  title 'The vAMI configuration file must be owned by root.'
  desc 'Log records can be generated from various components within the application server, (e.g., httpd, beans, etc.) From an application perspective, certain specific application functionalities may be logged, as well. The list of logged events is the set of events for which logs are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating log records (e.g., logable events, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked). Application servers utilize role-based access controls in order to specify the individuals who are allowed to configure application component logable events. The application server must be configured to select which personnel are assigned the role of selecting which logable events are to be logged. The personnel or roles that can select logable events are only the ISSM (or individuals or roles appointed by the ISSM).'
  desc 'check', 'At the command prompt, execute the following command:

ls -lL /opt/vmware/etc/sfcb/sfcb.cfg

If the sfcb.cfg file is not owned by root, this is a finding.'
  desc 'fix', 'At the command prompt, enter the following command:

chown root:root /opt/vmware/etc/sfcb/sfcb.cfg'
  impact 0.5
  ref 'DPMS Target vRealize Automation 7.x VAMI'
  tag check_id: 'C-89891r1_chk'
  tag severity: 'medium'
  tag gid: 'V-90199'
  tag rid: 'SV-100849r1_rule'
  tag stig_id: 'VRAU-VA-000055'
  tag gtitle: 'SRG-APP-000090-AS-000051'
  tag fix_id: 'F-96941r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
