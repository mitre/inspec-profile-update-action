control 'SV-221174' do
  title 'MongoDB must use NIST FIPS 140-2-validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data. Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of MongoDB.

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2-validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

The security functions validated as part of FIPS 140-2 for cryptographic modules are described in FIPS 140-2 Annex A.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

'
  desc 'check', 'If MongoDB is deployed in a classified environment:

In the MongoDB database configuration file (default location: /etc/mongod.conf), search for and review the following parameters:

net:
ssl:
FIPSMode: true

If this parameter is not present in the configuration file, this is a finding.

If "FIPSMode" is set to "false", this is a finding.

Check the server log file for a message that FIPS is active:
Search the log for the following text ""FIPS 140-2 mode activated"".

If this text is not found, this is a finding.

Verify that FIPS has been enabled at the operating system. The following will return "1" if FIPS is enabled:
cat /proc/sys/crypto/fips_enabled

If the above command does not return "1", this is a finding.'
  desc 'fix', 'Enable FIPS 140-2 mode for MongoDB Enterprise.

Edit the MongoDB database configuration file (default location: /etc/mongod.conf) to contain the following parameter setting:

net:
ssl:
FIPSMode: true

Stop/start (restart) the mongod or mongos instance using this configuration.

For the operating system finding, please refer to the appropriate operating system documentation for the procedure to install, configure, and test FIPS mode.'
  impact 0.7
  ref 'DPMS Target MongoDB Enterprise Advanced 3.x'
  tag check_id: 'C-22889r411016_chk'
  tag severity: 'high'
  tag gid: 'V-221174'
  tag rid: 'SV-221174r411018_rule'
  tag stig_id: 'MD3X-00-000380'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-22878r411017_fix'
  tag satisfies: ['SRG-APP-000179-DB-000114', 'SRG-APP-000514-DB-000381', 'SRG-APP-000514-DB-000382', 'SRG-APP-000514-DB-000383', 'SRG-APP-000416-DB-000380']
  tag 'documentable'
  tag legacy: ['SV-96589', 'V-81875']
  tag cci: ['CCI-000803', 'CCI-002450']
  tag nist: ['IA-7', 'SC-13 b']
end
