control 'SV-251655' do
  title 'The DBMS must associate organization-defined types of security labels having organization-defined security label values with information in process.'
  desc 'Without the association of security labels to information, there is no basis for the DBMS to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. 

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies; reflect special dissemination, handling, or distribution instructions; or support other aspects of the information security policy. 

One example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

The mechanism used to support security labeling may be a feature of the DBMS product, a third-party product, or custom application code.'
  desc 'check', 'If the site system plan does not require security labels, this requirement is Not Applicable.

Consult the system DBA and review system procedures for an application that maintains security label processing.

If there is no label application procedure, this is a finding.'
  desc 'fix', 'Update an application DB to include label fields in each database record and to maintain the status through the application.'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55093r807839_chk'
  tag severity: 'medium'
  tag gid: 'V-251655'
  tag rid: 'SV-251655r855292_rule'
  tag stig_id: 'IDMS-DB-000940'
  tag gtitle: 'SRG-APP-000313-DB-000309'
  tag fix_id: 'F-55047r807840_fix'
  tag 'documentable'
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']
end
