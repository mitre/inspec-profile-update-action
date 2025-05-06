control 'SV-220376' do
  title 'MarkLogic Server must associate organization-defined types of security labels having organization-defined security label values with information in transmission.'
  desc 'Without the association of security labels to information, there is no basis for the DBMS to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information. 

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies; reflect special dissemination, handling, or distribution instructions; or support other aspects of the information security policy. 

One example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, and it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

The mechanism used to support security labeling may be a feature of the DBMS product, a third-party product, or custom application code.'
  desc 'check', 'MarkLogic supports role-based access control for all entities/documents maintained within the database. User roles and applied document permissions determine access.

For example, if a document has read permission for role1 and read permission for role2, a user who possesses either role1 or role2 can read that document. Permissions in this example are evaluated using "OR" semantics.

Adding a Compartment to a role ensures access controls are evaluated using "AND" semantics when determining user access to a given resource. This security level is applied to the entire document/resource.

1. Verify applicable roles are configured with the necessary access Compartments for the specified role.
2. Verify all documents inserted into the MarkLogic database have the applicable permission (Compartment) applied.

If applicable roles do not have Compartments defined, this is a finding.

If documents inserted into the database do not have the applicable document permissions (Compartments) applied, this is a finding.

Additionally, MarkLogic can enforce Element-Level Security and Element Redaction ensuring users can only access specific elements of information they are permitted to access. Data a user is not permitted to see may be redacted or excluded all together.

Element-Level Security also ensures document searches do not return results where the search value is within an Element to which the user does not have access. This security level is applied to specified elements within a given document.

When/where applicable:
1. Navigate to the MarkLogic Admin page >> Security >> Protected Paths.
2. Verify the applicable elements requiring additional protections are defined using an XQuery path expression (applicable for both XML and JSON document types).
3. Verify the applicable role(s) are added against the specified path expression.

If specific document elements require additional protections and no Protected Paths or Protect Path roles are defined, this is a finding.'
  desc 'fix', 'See specific MarkLogic documentation regarding Compartment level security for necessary steps.

Applying Document Compartment Security:
1. Navigate to the MarkLogic Admin page >> Security >> Roles.
2. Create a new role and assign applicable roles/permissions.
3. Provide a Compartment name to the role.
4. Ensure all data ingestion mechanisms (i.e., document insertion code/logic) apply the necessary applicable security permissions.

Applying Element-Level Security:
1. Navigate to the MarkLogic Admin page >> Security >> Protected Paths.
2. Create a Protected Path by specifying an XQuery path expression identifying the element requiring specific protections.
3. Add one or more applicable roles and specify their capability then save the configuration.
4. Repeat step 3 for each element requiring additional protections.'
  impact 0.5
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22091r855479_chk'
  tag severity: 'medium'
  tag gid: 'V-220376'
  tag rid: 'SV-220376r855480_rule'
  tag stig_id: 'ML09-00-006500'
  tag gtitle: 'SRG-APP-000314-DB-000310'
  tag fix_id: 'F-22080r401580_fix'
  tag 'documentable'
  tag legacy: ['SV-110101', 'V-100997']
  tag cci: ['CCI-002264']
  tag nist: ['AC-16 a']
end
