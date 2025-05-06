control 'SV-204781' do
  title 'The application server must associate organization-defined types of security attributes having organization-defined security attribute values with information in transmission.'
  desc 'The application server provides a framework for applications to communicate between each other to form an overall well-designed application to perform a task.  As the information is transmitted, the security attributes must be maintained.  Without the association of security attributes to information, there is no basis for the application to make security-related access control decisions.

Security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

One example includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing, but either way, it is imperative these assignments are maintained while the data is in transmission. If the security attributes are lost when the data is being transmitted, there is the risk of a data compromise.'
  desc 'check', 'Review the application server documentation to determine if the application associates organization-defined types of security attributes with organization-defined security attribute values to information in transmission.

If the application server does not associate the security attributes to information in transmission or the feature is not implemented, this is a finding.'
  desc 'fix', 'Configure the application server to associate organization-defined types of security attributes having organization-defined security attribute values with information in transmission.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4901r282990_chk'
  tag severity: 'medium'
  tag gid: 'V-204781'
  tag rid: 'SV-204781r879691_rule'
  tag stig_id: 'SRG-APP-000314-AS-000005'
  tag gtitle: 'SRG-APP-000314'
  tag fix_id: 'F-4901r282991_fix'
  tag 'documentable'
  tag legacy: ['SV-71681', 'V-57409']
  tag cci: ['CCI-002264']
  tag nist: ['AC-16 a']
end
