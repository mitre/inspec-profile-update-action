control 'SV-204718' do
  title 'The application server must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which logable events are to be logged.'
  desc 'Log records can be generated from various components within the application server, (e.g., httpd, beans, etc.) From an application perspective, certain specific application functionalities may be logged, as well.

The list of logged events is the set of events for which logs are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating log records (e.g., logable events, time stamps, source and destination addresses, user/process identifiers, event descriptions, success/fail indications, filenames involved, and access control or flow control rules invoked).


Application servers utilize role-based access controls in order to specify the individuals who are allowed to configure application component logable events. The application server must be configured to select which personnel are assigned the role of selecting which logable events are to be logged.

The personnel or roles that can select logable events are only the ISSM (or individuals or roles appointed by the ISSM).'
  desc 'check', 'Review application server product documentation and configuration to determine if the system only allows the ISSM (or individuals or roles appointed by the ISSM) to change logable events.

If the system is not configured to perform this function, this is a finding.'
  desc 'fix', 'Configure the application server to only allow the ISSM (or individuals or roles appointed by the ISSM) to change logable events.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4838r282801_chk'
  tag severity: 'medium'
  tag gid: 'V-204718'
  tag rid: 'SV-204718r879560_rule'
  tag stig_id: 'SRG-APP-000090-AS-000051'
  tag gtitle: 'SRG-APP-000090'
  tag fix_id: 'F-4838r282802_fix'
  tag 'documentable'
  tag legacy: ['V-35142', 'SV-46429']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
