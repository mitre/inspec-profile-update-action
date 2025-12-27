control 'SV-224188' do
  title 'The EDB Postgres Advanced Server must associate organization-defined types of security labels having organization-defined security label values with information in storage.'
  desc 'Without the association of security labels to information, there is no basis for EDB Postgres Advanced Server to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling or distribution instructions, or support other aspects of the information security policy.

One example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

The mechanism used to support security labeling may be a feature of EDB Postgres Advanced Server, a third-party product, or custom application code.

In addition to being able to grant privileges on tables using standard SQL features, EDB Postgres Advanced Server provides a Row Level Security (RLS) feature. This feature provides the ability to define and enable row-level security policies that restrict insert, update, delete, and select access on the rows of a table on a per user basis. For deployments within the DoD, RLS policies are configured to use the assigned security labels.'
  desc 'check', "If security labeling is not required, this is not a finding.

If security labeling requirements have been specified, execute the following SQL as enterprisedb:

 SELECT * from ALL_POLICIES where OBJECT_NAME = '<table name>';

If a policy is not enabled for the table requiring security labeling, this is a finding.

If security labeling is required and not implemented according to the system documentation, this is a finding.

If security labeling requirements have been specified, but neither a third-party solution nor an EDB Postgres Advanced Server Row-Level security solution is implemented that reliably maintains labels on information in storage, this is a finding."
  desc 'fix', 'Deploy EDB Postgres Advanced Server Row-Level Security (see link below) or a third-party software, or add custom data structures, data elements, and application code, to provide reliable security labeling of information in storage.

https://www.enterprisedb.com/docs/en/11.0/EPAS_BIP_Guide_v11/Database_Compatibility_for_Oracle_Developers_Built-in_Package_Guide.1.31.html#pID0E0UUD0HA'
  impact 0.5
  ref 'DPMS Target EDB Postgres Advanced Server v11 on Windows'
  tag check_id: 'C-25861r495582_chk'
  tag severity: 'medium'
  tag gid: 'V-224188'
  tag rid: 'SV-224188r508023_rule'
  tag stig_id: 'EP11-00-006900'
  tag gtitle: 'SRG-APP-000311-DB-000308'
  tag fix_id: 'F-25849r495583_fix'
  tag 'documentable'
  tag legacy: ['V-100399', 'SV-109503']
  tag cci: ['CCI-002262']
  tag nist: ['AC-16 a']
end
