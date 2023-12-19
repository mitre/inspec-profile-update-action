control 'SV-252161' do
  title 'MongoDB must map the PKI-authenticated identity to an associated user account.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates. Once a PKI certificate has been validated, it must be mapped to a DBMS user account for the authenticated identity to be meaningful to MongoDB and useful for authorization decisions.'
  desc 'check', 'If using LDAP for authentication, this is not applicable.

Each unique x.509 client certificate corresponds to a single MongoDB user; meaning it cannot use a single-client certificate to authenticate more than one MongoDB user.

Log in to MongoDB and run the following command:

 db.runCommand( {connectionStatus: 1} );

Example output being:

 db.runCommand({connectionStatus:1}).authInfo
{
    "authenticatedUsers" : [
        {
            "user" : "CN=myName,OU=myOrgUnit,O=myOrg,L=myLocality,ST=myState,C=myCountry",
            "db" : "mydb1"
        }
    ],
    "authenticatedUserRoles" : [
        {
            "role" : dbOwner,
            "db" : "mydb1"
        }
    ]
}

If the authenticated MongoDB user displayed does not have a user value equal to the x.509 certs Subject Name, this is a finding.'
  desc 'fix', 'Add x.509 Certificate subject as an authorized user.

To authenticate with a client certificate, first add the value of the subject from the client certificate as a MongoDB user. 

Each unique x.509 client certificate corresponds to a single MongoDB user; meaning it cannot use a single-client certificate to authenticate more than one MongoDB user.

Note: The RDNs in the subject string must be compatible with the RFC2253 standard.

Retrieve the RFC2253 formatted subject from the client certificate with the following command:

openssl x509 -in pathToClient PEM -inform PEM -subject -nameopt RFC2253

The command returns the subject string as well as certificate:

subject= CN=myName,OU=myOrgUnit,O=myOrg,L=myLocality,ST=myState,C=myCountry
-----BEGIN CERTIFICATE-----
# ...
-----END CERTIFICATE-----

Add the RFC2253 compliant value of the subject as a user. Omit spaces as needed.

For example, in the mongo shell, to add the user with both the readWrite role in the test database and the userAdminAnyDatabase role which is defined only in the admin database:

 db.getSiblingDB("$external").runCommand(
  {
    createUser: "CN=myName,OU=myOrgUnit,O=myOrg,L=myLocality,ST=myState,C=myCountry",
    roles: [
             { role: readWrite, db: test },
             { role: userAdminAnyDatabase, db: admin }
           ],
    writeConcern: { w: "majority" , wtimeout: 5000 }
  }
)

In the above example, to add the user with the readWrite role in the test database, the role specification document specified test in the db field. 

To add userAdminAnyDatabase role for the user, the above example specified admin in the db field.

Note: Some roles are defined only in the admin database, including: clusterAdmin, readAnyDatabase, readWriteAnyDatabase, dbAdminAnyDatabase, and userAdminAnyDatabase. 

To add a user with these roles, specify admin in the db field. See Manage Users and Roles for details on adding a user with roles.

To remove a user that is not authorized run the following command:

 use $external
 db.dropUser(%RDN of user%)'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55617r813863_chk'
  tag severity: 'medium'
  tag gid: 'V-252161'
  tag rid: 'SV-252161r813865_rule'
  tag stig_id: 'MD4X-00-003200'
  tag gtitle: 'SRG-APP-000177-DB-000069'
  tag fix_id: 'F-55567r813864_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
