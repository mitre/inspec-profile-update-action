control 'SV-252144' do
  title 'MongoDB must associate organization-defined types of security labels having organization-defined security label values with information in storage and transmission.'
  desc 'Without the association of security labels to information, there is no basis for MongoDB to make security-related access-control decisions.

Security labels are abstractions representing the basic properties or characteristics of an entity (e.g., subjects and objects) with respect to safeguarding information.

These labels are typically associated with internal data structures (e.g., tables, rows) within the database and are used to enable the implementation of access control and flow control policies, reflect special dissemination, handling, or distribution instructions, or support other aspects of the information security policy.

One example includes marking data as classified or CUI. These security labels may be assigned manually or during data processing, but, either way, it is imperative these assignments are maintained while the data is in storage. If the security labels are lost when the data is stored, there is the risk of a data compromise.

The mechanism used to support security labeling may be a feature of MongoDB product, a third-party product, or custom application code.

'
  desc 'check', 'If security labeling is not required, this is not a finding. 

If security labeling is required, then there must be organizational or site-specific documentation on what the security labeling policy is and guidance on how and where to apply it.
  
Review the organizational or site-specific security labeling documentation to understand how documents in specific MongoDB collection(s) must be marked. This marking process should be applied as data is entered into the database.

Upon review of the security labeling documents,  the following checks will be required.

1. Check if the role SLTagViewer exists. 
If this role does not exist this is a finding.

Note: The role name SLTagViewer is a user-defined (custom) role and is organizational or site-specific. The role name of SLTagViewer is used here as an example.

Run the following commands:

 use admin
 db.getRole( "SLTagViewer", { showPrivileges: true } )

If the results returned from this command is null, this is a finding.
 
2. Check that data is appropriately marked in the specific MongoDB collection(s) that require security labeling. This check will be specific to the security labeling policy and guidance.

Log in to MongoDB with a user that has a Security Label Tag Viewer role (SLTagViewer, which is a role that has been created and has access to read/view those database/collections that require security labels) and review the data in the MongoDB collections that require security labels to ensure that the data is appropriately marked according to the security labeling documentation.
  
For example, if documents in a MongoDB collection need to be marked as TS, S, C or U (or combination of) at the root level of the document and at each field level of the document then the security labeling policy and guidance would indicate a document might look like the following and this  would be not be a finding (sl is the security label):
{
    "_id": 1,
    "sl": [["TS", ["S"]],
    "field1" : { "sl" : [ ["S"] ], "data" : "field1 value" },
    "field2" : { "sl" : [ ["TS"] ], "data" : "field2 value" },
    "field3" : { "sl" : [ ["S"] ], "data" : "field3 value" }
}

The following document would be a finding because at the field level, field2 is missing its security label of sl:

{
    "_id": 1,
    "sl": [["TS"], ["S"]],
    "field1" : { "sl" : [ ["S"] ], "data" : "field1 value" },
    "field2" : { "data" : "field2 value" },
    "field3" : { "sl" : [ ["S"] ], "data" : "field3 value" }
}

3. Check that queries against that data in those collections use an appropriately constructed MongoDB $redact operation as part of the query pipeline to ensure that only the data appropriate for the query (that meets the security label requirements) is returned.  

Ensure that any query that targets the databases/collections that have security labeling have the appropriate MongoDB $redact operation applied.  

This is done through trusted middleware. This trusted middleware configuration is purpose built (custom) code and integrations and is organizational or site-specific. Information on the basics of how this is can be constructed can be found here: https://docs.mongodb.com/v4.4/reference/operator/aggregation/redact/

Any queries that target a MongoDB database/collection that has security labels and that pass through the trusted middleware and does not have an appropriately constructed $redact operator which is part of the query aggregation pipeline are a finding.

The following is an example of the $redact operator for the example document:

 db.security_collection.aggregate(
[{ 
   $redact:
    { $cond: [{ $anyElementTrue:
          { $map: { input: "$sl",
              as: "setNeeded",
                in: { $setIsSubset: 
                ["$$setNeeded", ["S"]] }
               }
          }
          },
          "$$DESCEND", "$$PRUNE"]
    }
}
]
)'
  desc 'fix', 'If security labeling is required then ensure the following:

1. Organizational or site-specific documentation and guidance is available or developed.
2. Ensure that security labels are or have been applied to those MongoDB collection(s) requiring them in accordance with the organization or site specific documentation.
3. Create a Security Label Tag Viewer role (SLTagViewer) with find privileges on the specific database and collection that requires security labeling.  

The example below shows three databases and collections in those databases where security labels are required.

 use admin
 db.createRole(
   {
     role: "SLTagViewer",
     privileges: [
       { resource: { db: "db1", collection: "coll1" }, actions: [ "find" ] },
       { resource: { db: "db1", collection: "coll2" }, actions: [ "find" ] },
       { resource: { db: "db1", collection: "coll3" }, actions: [ "find" ] },
       { resource: { db: "db2", collection: "coll1" }, actions: [ "find" ] },
       { resource: { db: "db2", collection: "coll5" }, actions: [ "find" ] },
       { resource: { db: "db2", collection: "coll9" }, actions: [ "find" ] },
       { resource: { db: "db3", collection: "coll81" }, actions: [ "find" ] }
     ],
     roles: [ ]
   },
   { w: "majority" , wtimeout: 5000 }
) 

4. Ensure that any query that targets the databases/collections that have security labeling have the appropriate MongoDB $redact operation applied.

The $redact operator is applied through trusted middleware. This trusted middleware configuration is purpose-built (custom) code and integrations and is organizational or site-specific. Information on the basics of how this is can be constructed can be found here: https://docs.mongodb.com/v4.4/reference/operator/aggregation/redact/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55600r817000_chk'
  tag severity: 'medium'
  tag gid: 'V-252144'
  tag rid: 'SV-252144r817017_rule'
  tag stig_id: 'MD4X-00-001100'
  tag gtitle: 'SRG-APP-000311-DB-000308'
  tag fix_id: 'F-55550r817016_fix'
  tag satisfies: ['SRG-APP-000311-DB-000308', 'SRG-APP-000313-DB-000309', 'SRG-APP-000314-DB-000310']
  tag 'documentable'
  tag cci: ['CCI-002262', 'CCI-002263', 'CCI-002264']
  tag nist: ['AC-16 a', 'AC-16 a', 'AC-16 a']
end
