control 'SV-222394' do
  title 'The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in process.'
  desc 'Without the association of security attributes to information, there is no basis for the application to make security related access-control decisions.

Security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These attributes are typically associated with internal data structures (e.g., records, buffers, files) within the information system and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy.

One example includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing but either way, it is imperative these assignments are maintained while the data is in process. If the security attributes are lost when the data is being processed, there is the risk of a data compromise.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Identify if the application requirements include data marking.  Also determine if the application processes classified, FOUO or other data that is required to be marked.

If the application does not contain classified, FOUO or have data marking requirements, this requirement is not applicable.

Access the user interface for the application and navigate through the application. Perform several application actions that will manipulate data contained within the application.

For example, create a test record and assign a data marking to the data element. Save the test record, close the data entry fields and navigate to display the test record. Perform an edit action on the test data that does not edit the marking itself or perform any other form of data processing such as assigning the data to another users work queue for review or printing the data, ensure the data marking is retained throughout the data processing actions.

If application data required to be marked does not retain its marking while it is being processed by the application, this is a finding.'
  desc 'fix', 'Design and configure the application to retain the data marking when processing data.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24064r493090_chk'
  tag severity: 'medium'
  tag gid: 'V-222394'
  tag rid: 'SV-222394r849422_rule'
  tag stig_id: 'APSC-DV-000120'
  tag gtitle: 'SRG-APP-000313'
  tag fix_id: 'F-24053r493091_fix'
  tag 'documentable'
  tag legacy: ['SV-83875', 'V-69253']
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']
end
