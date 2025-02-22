control 'SV-204780' do
  title 'The application server must associate organization-defined types of security attributes having organization-defined security attribute values with information in process.'
  desc 'The application server provides a framework for applications to communicate between each other to form an overall well-designed application to perform a task.  As the information traverses the application server and the components, the security attributes must be maintained.  Without the association of security attributes to information, there is no basis for the application server or hosted applications to make security-related access control decisions.  The security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

One example includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing, but either way, it is imperative these assignments are maintained while the data is in process. If the security attributes are lost when the data is being processed, there is the risk of a data compromise.'
  desc 'check', 'Review the application server documentation to determine if the application associates organization-defined types of security attributes with organization-defined security attribute values to information in process.

If the application server does not associate the security attributes to information in process or the feature is not implemented, this is a finding.'
  desc 'fix', 'Configure the application server to associate organization-defined types of security attributes having organization-defined security attribute values with information in process.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4900r282987_chk'
  tag severity: 'medium'
  tag gid: 'V-204780'
  tag rid: 'SV-204780r850836_rule'
  tag stig_id: 'SRG-APP-000313-AS-000003'
  tag gtitle: 'SRG-APP-000313'
  tag fix_id: 'F-4900r282988_fix'
  tag 'documentable'
  tag legacy: ['V-57407', 'SV-71679']
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']
end
