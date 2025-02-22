control 'SV-252146' do
  title 'MongoDB must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.'
  desc 'The use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data.  Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of MongoDB.

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 or 140-3 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The standard for validating cryptographic modules will transition to the NIST FIPS 140-3 publication.

FIPS 140-2 modules can remain active for up to five years after validation or until September 21, 2026, when the FIPS 140-2 validations will be moved to the historical list. Even on the historical list, CMVP supports the purchase and use of these modules for existing systems. While Federal Agencies decide when they move to FIPS 140-3 only modules, purchasers are reminded that for several years there may be a limited selection of FIPS 140-3 modules from which to choose. CMVP recommends purchasers consider all modules that appear on the Validated Modules Search Page:
https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules

More information on the FIPS 140-3 transition can be found here: 
https://csrc.nist.gov/Projects/fips-140-3-transition-effort/

'
  desc 'check', 'Run the following command from the MongoDB shell:

 db.getSiblingDB("admin").runCommand({getCmdLineOpts: 1}).parsed.net.tls.FIPSMode

If the MongoDB server is running with FIPS mode, this command will return true. Any other output is a finding.

Verify that FIPS has been enabled at the OS level. Refer to the appropriate OS STIG documentation.'
  desc 'fix', 'Enable FIPS mode for MongoDB Enterprise.

Edit the MongoDB database configuration file (default location: /etc/mongod.conf) to contain the following parameter setting:

net:
   tls:
      FIPSMode: true

Stop/start (restart) the mongod or mongos instance using this configuration and run the following command to verify the output is true:

db.getSiblingDB("admin").runCommand({getCmdLineOpts: 1}).parsed.net.tls.FIPSMode
true

Alternatively, run the following command to search the mongod logfile for FIPS 140-2 mode activated:

grep "FIPS 140-2 mode activated" /var/log/mongodb/mongod.log

For the operating system finding, refer to the appropriate operating system documentation for the procedure to install, configure, and test FIPS mode.'
  impact 0.7
  ref 'DPMS Target MongoDB Enterprise Advanced 4.x'
  tag check_id: 'C-55602r813818_chk'
  tag severity: 'high'
  tag gid: 'V-252146'
  tag rid: 'SV-252146r863331_rule'
  tag stig_id: 'MD4X-00-001300'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-55552r863330_fix'
  tag satisfies: ['SRG-APP-000179-DB-000114', 'SRG-APP-000416-DB-000380', 'SRG-APP-000514-DB-000381', 'SRG-APP-000514-DB-000382', 'SRG-APP-000514-\nDB-000383']
  tag 'documentable'
  tag cci: ['CCI-002450', 'CCI-000803']
  tag nist: ['SC-13 b', 'IA-7']
end
