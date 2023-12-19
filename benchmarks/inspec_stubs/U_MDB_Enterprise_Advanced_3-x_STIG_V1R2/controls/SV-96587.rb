control 'SV-96587' do
  title 'MongoDB must map the PKI-authenticated identity to an associated user account.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates. Once a PKI certificate has been validated, it must be mapped to a DBMS user account for the authenticated identity to be meaningful to MongoDB and useful for authorization decisions.'
  desc 'check', 'To authenticate with a client certificate, you must first add the value of the subject from the client certificate as a MongoDB user. 

Each unique x.509 client certificate corresponds to a single MongoDB user; i.e. you cannot use a single client certificate to authenticate more than one MongoDB user.

Login to MongoDB and run the following command:

use $external
db.getUsers()

If the output does not contain a Relative Distinguished Name (RDN) for an authorized user, this is a finding.

If the output shows a Relative Distinguished Name (RDN) for users that are not authorized, this is a finding.'
  desc 'fix', %q(Add x.509 Certificate subject as an authorized user.

To authenticate with a client certificate, you must first add the value of the subject from the client certificate as a MongoDB user. 

Each unique x.509 client certificate corresponds to a single MongoDB user; i.e. you cannot use a single client certificate to authenticate more than one MongoDB user.

Note: The RDNs in the subject string must be compatible with the RFC2253 standard.

Retrieve the RFC2253 formatted subject from the client certificate with the following command:
openssl x509 -in <pathToClient PEM> -inform PEM -subject -nameopt RFC2253

The command returns the subject string as well as certificate:
subject= CN=myName,OU=myOrgUnit,O=myOrg,L=myLocality,ST=myState,C=myCountry
-----BEGIN CERTIFICATE-----
# ...
-----END CERTIFICATE-----

Add the RFC2253 compliant value of the subject as a user. Omit spaces as needed.

For example, in the mongo shell, to add the user with both the "readWrite" role in the test database and the "userAdminAnyDatabase" role which is defined only in the admin database:
db.getSiblingDB("$external").runCommand(
{
createUser: "CN=myName,OU=myOrgUnit,O=myOrg,L=myLocality,ST=myState,C=myCountry",
roles: [
{ role: 'readWrite', db: 'test' },
{ role: 'userAdminAnyDatabase', db: 'admin' }
],
writeConcern: { w: "majority" , wtimeout: 5000 }
}
)

In the above example, to add the user with the "readWrite" role in the test database, the role specification document specified "test" in the "db" field. To add "userAdminAnyDatabase" role for the user, the above example specified "admin" in the "db" field.

Note: Some roles are defined only in the admin database, including: clusterAdmin, readAnyDatabase, readWriteAnyDatabase, dbAdminAnyDatabase, and userAdminAnyDatabase. To add a user with these roles, specify "admin" in the "db" field. See Manage Users and Roles for details on adding a user with roles.

To remove a user that is not authorized run the following command:

use $external
db.dropUser("<RDN of user>"))
  impact 0.5
  ref 'DPMS Target MongoDB 3.x'
  tag check_id: 'C-81665r1_chk'
  tag severity: 'medium'
  tag gid: 'V-81873'
  tag rid: 'SV-96587r1_rule'
  tag stig_id: 'MD3X-00-000370'
  tag gtitle: 'SRG-APP-000177-DB-000069'
  tag fix_id: 'F-88723r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
