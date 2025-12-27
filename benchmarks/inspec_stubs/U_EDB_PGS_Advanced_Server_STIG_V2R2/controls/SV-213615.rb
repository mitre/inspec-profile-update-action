control 'SV-213615' do
  title 'The EDB Postgres Advanced Server must associate organization-defined types of security labels having organization-defined security label values with information in process.'
  desc 'Without the association of security labels to information, there is no basis for the DBMS to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. 

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy. 

One example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

The mechanism used to support security labeling may be a feature of the DBMS product, a third-party product, or custom application code.'
  desc 'check', "If security labeling is not required, this is not applicable (NA).

If security labeling requirements have been specified, execute the following SQL as enterprisedb:

SELECT * from ALL_POLICIES where OBJECT_NAME = '<table name>';

If a policy is not enabled for the table requiring security labeling, this is a finding."
  desc 'fix', 'Create a row-level policy for all required tables as defined here: 

http://www.enterprisedb.com/docs/en/9.5/oracompat/Database_Compatibility_for_Oracle_Developers_Guide.1.201.html#pID0E0D5J0HA'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14837r290157_chk'
  tag severity: 'medium'
  tag gid: 'V-213615'
  tag rid: 'SV-213615r508024_rule'
  tag stig_id: 'PPS9-00-007000'
  tag gtitle: 'SRG-APP-000313-DB-000309'
  tag fix_id: 'F-14835r290158_fix'
  tag 'documentable'
  tag legacy: ['SV-83587', 'V-68983']
  tag cci: ['CCI-002263']
  tag nist: ['AC-16 a']
end
