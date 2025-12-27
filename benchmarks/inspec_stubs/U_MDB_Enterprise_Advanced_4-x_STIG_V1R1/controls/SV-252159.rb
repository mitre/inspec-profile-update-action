control 'SV-252159' do
  title 'If passwords are used for authentication, MongoDB must store only hashed, salted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, database passwords stored in clear text, using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to MongoDB.'
  desc 'check', 'MongoDB supports several authentication mechanisms, some of which store credentials on the MongoDB server. 

If these mechanisms are in use, MongoDBs authSchemaVersion in the admin.system.version collection must be set to 5.

1. Validate that authenticationMechansisms is defined in config file (default location /etc/mongod.conf).

The MongoDB Configuration file should contain the similar to the following entry:

setParameter:
  authenticationMechanisms: SCRAM-SHA-256 

If the config file does not contain an authenticationMechanisms entry, this is a finding.

2. Validate authSchemaVersion is set to 5.

  Using the shell, run the following command:

 db.getSiblingDB("admin").system.version.find({ "_id" : "authSchema"}, {_id: 0})

  It should return:
    { "currentVersion" : 5 }

If currentVersion is less than 5, this is a finding.'
  desc 'fix', '1. If authenticationMechanisms is not defined in the %MongoDB configuration file% (default location: /etc/mongod.conf), define one of more authenticationMechanisms, from the subset below:

SCRAM-SHA-1
SCRAM-SHA-256
MONGODB-X509
GSSAPI
PLAIN

which the MongoDB server process must accept.

Example:

setParameter:
  authenticationMechanisms: SCRAM-SHA-1,SCRAM-SHA-256

2. If authSchemaVersion is less than 5.

Run the following command:

 db.adminCommand({authSchemaUpgrade: 1})

In the unlikely event that an error is encountered, safely rerun the authSchemaUpgrade command.'
  impact 0.5
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55615r817003_chk'
  tag severity: 'medium'
  tag gid: 'V-252159'
  tag rid: 'SV-252159r817005_rule'
  tag stig_id: 'MD4X-00-003000'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-55565r817004_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
