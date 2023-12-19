control 'SV-221185' do
  title 'MongoDB must associate organization-defined types of security labels having organization-defined security label values with information in storage.'
  desc 'Without the association of security labels to information, there is no basis for MongoDB to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling, or distribution instructions, or support other aspects of the information security policy.

One example includes marking data as classified or FOUO. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

The mechanism used to support security labeling may be a feature of MongoDB product, a third-party product, or custom application code.

'
  desc 'check', 'MongoDB supports role-based access control at the collection level. If enabled, the database process should be started with "security.authorization:enabled" in the config file or with "--auth" in the command line.

For documents that have been labeled (e.g., {"tag" : "classified"}), read-only views can be created and secured via access privileges such that a user can only view those documents that have a specific tag or tags (e.g., user x can only view records that are labeled with the tag of classified). Existing views can be listed using the db.getCollectionInfos() command for the selected database in mongo shell. 

If a view is not present for the collection requiring security labeling, this is a finding.

MongoDB supports field-level redaction that allows the application to indicate to the database whether or not certain fields should be returned based on values in the field labels. 

If desired and aggregation queries in the application code are not using the $redact stage with appropriate logic, this is a finding.'
  desc 'fix', 'Follow the documentation page to setup RBAC:https://docs.mongodb.com/manual/core/authorization/. 

For the required collections, create specific read-only views that allow access to only a subset of the data in a collection as documented here: https://docs.mongodb.com/manual/core/views/. Permissions on the view are specified separately from the permissions on the underlying collection.

Use the "$redact" operator to restrict the contents of the documents based on information stored in the documents themselves as documented here: https://docs.mongodb.com/master/reference/operator/aggregation/redact/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22900r411049_chk'
  tag severity: 'medium'
  tag gid: 'V-221185'
  tag rid: 'SV-221185r411051_rule'
  tag stig_id: 'MD3X-00-000540'
  tag gtitle: 'SRG-APP-000311-DB-000308'
  tag fix_id: 'F-22889r411050_fix'
  tag satisfies: ['SRG-APP-000311-DB-000308', 'SRG-APP-000313-DB-000309', 'SRG-APP-000313-DB-000310']
  tag 'documentable'
  tag legacy: ['SV-96611', 'V-81897']
  tag cci: ['CCI-002262', 'CCI-002263', 'CCI-002264']
  tag nist: ['AC-16 a', 'AC-16 a', 'AC-16 a']
end
