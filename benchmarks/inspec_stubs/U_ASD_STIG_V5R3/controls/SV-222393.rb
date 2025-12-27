control 'SV-222393' do
  title 'The application must associate organization-defined types of security attributes having organization-defined security attribute values with information in storage.'
  desc 'Without the association of security attributes to information, there is no basis for the application to make security related access-control decisions.

Security attributes are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These attributes are typically associated with internal data structures (e.g., records, buffers, files) within the information system and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy.

One example includes marking data as classified or FOUO. These security attributes may be assigned manually or during data processing but either way, it is imperative these assignments are maintained while the data is in storage. If the security attributes are lost when the data is stored, there is the risk of a data compromise.

Classify the system hosting the application with default classification.  Treat all unmarked data at the highest classification as the overall hosting system is classified.  If there is no classification, mark system high.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Determine if the application processes classified, FOUO, or other data that is required to be marked and identify if the application requirements specify data markings of any other types of data.

If the application does not contain classified, FOUO, or other data that is required to be marked, this requirement is not applicable.

Review the database or other storage mechanism and have the application administrator identify and demonstrate how the application assigns and maintains data markings while the data is in storage.

Typical methods for marking data include utilizing a table or data base field that contains the marking information and associating the marking information with the data.

If application data required to be marked is not marked and does not retain its marking while it is being stored, this is a finding.'
  desc 'fix', 'Design and configure the application to assign data marking and ensure the marking is retained when the data is stored.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24063r493087_chk'
  tag severity: 'medium'
  tag gid: 'V-222393'
  tag rid: 'SV-222393r879689_rule'
  tag stig_id: 'APSC-DV-000110'
  tag gtitle: 'SRG-APP-000311'
  tag fix_id: 'F-24052r493088_fix'
  tag 'documentable'
  tag legacy: ['SV-83873', 'V-69251']
  tag cci: ['CCI-002262']
  tag nist: ['AC-16 a']
end
