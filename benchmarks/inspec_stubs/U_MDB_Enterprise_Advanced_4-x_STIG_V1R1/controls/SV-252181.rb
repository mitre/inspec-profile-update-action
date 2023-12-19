control 'SV-252181' do
  title 'When invalid inputs are received, MongoDB must behave in a predictable and documented manner that reflects organizational and system objectives.'
  desc 'A common vulnerability is unplanned behavior when invalid inputs are received. This requirement guards against adverse or unintended system behavior caused by invalid inputs, where information system responses to the invalid input may be disruptive or cause the system to fail into an unsafe state.

The behavior will be derived from the organizational and system requirements and includes, but is not limited to, notification of the appropriate personnel, creating an audit record, and rejecting invalid input.

This calls for inspection of application source code, which will require collaboration with the application developers. It is recognized that in many cases, the database administrator (DBA) is organizationally separate from the application developers, and may have limited, if any, access to source code. Nevertheless, protections of this type are so important to the secure operation of databases that they must not be ignored. At a minimum, the DBA must attempt to obtain assurances from the development organization that this issue has been addressed, and must document what has been discovered.'
  desc 'check', 'This is application-specific, but see Schema Validation documentation here:
https://docs.mongodb.com/v4.4/core/schema-validation/

As an example, as a user with the dbAdminAnyDatabase role, execute the following on the database of interest:

 use database
 db.getCollectionInfos()

Where database is the name of the database on which validator rules are to be inspected. This returns an array of documents containing all collections information within the database. 

For all collections information received, check if the options sub-document contains a validator.

If the options sub-document does not contain a validator, this is a finding.

Example below shows a finding:
[
        {
                "name" : "inventory",
                "type" : "collection",
                "options" : {

                },
                "info" : {
                        "readOnly" : false,
                        "uuid" : UUID("b2c86d4d-48bf-4394-9743-620e6d68b87f")
                },
                "idIndex" : {
                        "v" : 2,
                        "key" : {
                                "_id" : 1
                        },
                        "name" : "_id_",
                        "ns" : "products.inventory"
                }
        }
]'
  desc 'fix', 'Document validation can be added at the time of creation of a new collection. 

Existing collections can also be modified with document validation rules. 

Use the validator option to create or update a collection with the desired validation rules. 

See Schema Validation documentation for details:
https://docs.mongodb.com/v4.4/core/schema-validation/'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55637r816994_chk'
  tag severity: 'medium'
  tag gid: 'V-252181'
  tag rid: 'SV-252181r816995_rule'
  tag stig_id: 'MD4X-00-006200'
  tag gtitle: 'SRG-APP-000447-DB-000393'
  tag fix_id: 'F-55587r813924_fix'
  tag 'documentable'
  tag cci: ['CCI-002754']
  tag nist: ['SI-10 (3)']
end
