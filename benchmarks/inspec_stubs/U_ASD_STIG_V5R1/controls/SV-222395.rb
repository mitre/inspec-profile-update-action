control 'SV-222395' do
  title 'The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in transmission.'
  desc 'Without the association of security attributes to information, there is no basis for the application to make security related access-control decisions.

Security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These attributes are typically associated with internal data structures (e.g., records, buffers, files) within the information system and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy.

One example includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing but either way, it is imperative these assignments are maintained while the data is in transmission. If the security attributes are lost when the data is being transmitted, there is the risk of a data compromise.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify if the application requirements include data marking also determine if the application processes classified, FOUO or other data that is required to be marked.

Access the user interface for the application and navigate through the application. Perform an application action that will transmit marked data that is contained within the application.

If the application does not contain classified, FOUO or have data marking requirements, or if the application does not transmit data, this requirement is not applicable.

E.g., create a test record and assign a data marking to the data element. Save the test record, close the data entry fields and navigate to display the test record. Initiate the application processes to transmit data. Access remote system or have person with access to remote system verify the data marking is retained after the data transmission.

If application data required to be marked does not retain its marking when it is being transmitted by the application, this is a finding.'
  desc 'fix', 'Design and configure the application to retain the data marking when transmitting data.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24065r493093_chk'
  tag severity: 'medium'
  tag gid: 'V-222395'
  tag rid: 'SV-222395r508029_rule'
  tag stig_id: 'APSC-DV-000130'
  tag gtitle: 'SRG-APP-000314'
  tag fix_id: 'F-24054r493094_fix'
  tag 'documentable'
  tag legacy: ['V-69255', 'SV-83877']
  tag cci: ['CCI-002264']
  tag nist: ['AC-16 a']
end
