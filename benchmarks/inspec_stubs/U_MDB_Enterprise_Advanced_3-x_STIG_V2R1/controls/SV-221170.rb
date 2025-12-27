control 'SV-221170' do
  title 'If passwords are used for authentication, MongoDB must store only hashed, salted representations of passwords.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates.

Authentication based on User ID and Password may be used only when it is not possible to employ a PKI certificate, and requires AO approval.

In such cases, database passwords stored in clear text using reversible encryption, or using unsalted hashes would be vulnerable to unauthorized disclosure. Database passwords must always be in the form of one-way, salted hashes when stored internally or externally to MongoDB.'
  desc 'check', 'MongoDB supports x.509 certificate authentication for use with a secure TLS/SSL connection.

The x.509 client authentication allows clients to authenticate to servers with certificates rather than with a username and password.

If X.509 authentication is not used, a SCRAM-SHA-1 authentication protocol is also available. The SCRAM-SHA-1 protocol uses one-way, salted hash functions for passwords as documented here: https://docs.mongodb.com/v3.4/core/security-scram-sha-1/

To authenticate with a client certificate, you must first add a MongoDB user that corresponds to the client certificate. See Add x.509 Certificate subject as a User as documented here: https://docs.mongodb.com/v3.4/tutorial/configure-x509-client-authentication/

To authenticate, use the db.auth() method in the $external database, specifying "MONGODB-X509" for the mechanism field, and the user that corresponds to the client certificate for the user field.

If the mechanism field is not set to "MONGODB-X509", this is a finding.'
  desc 'fix', 'Do the following:
- Create local CA and signing keys. 
- Generate and sign server certificates for member authentication. 
- Generate and sign client certificates for client authentication. 
- Start MongoDB cluster in non-auth mode. 
- Set up replica set and initial users. 
- Restart MongoDB replica set in X.509 mode using server certificates. 

Example shown here for x.509 Authentication: https://www.mongodb.com/blog/post/secure-mongodb-with-x-509-authentication

Additionally, SSL/TLS must be on as documented here: https://docs.mongodb.com/v3.4/tutorial/configure-ssl/'
  impact 0.7
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22885r411004_chk'
  tag severity: 'high'
  tag gid: 'V-221170'
  tag rid: 'SV-221170r822438_rule'
  tag stig_id: 'MD3X-00-000330'
  tag gtitle: 'SRG-APP-000171-DB-000074'
  tag fix_id: 'F-22874r411005_fix'
  tag 'documentable'
  tag legacy: ['SV-96581', 'V-81867']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
