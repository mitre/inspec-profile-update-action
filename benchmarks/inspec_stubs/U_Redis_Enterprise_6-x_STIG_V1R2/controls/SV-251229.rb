control 'SV-251229' do
  title 'Redis Enterprise DBMS must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data. Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

Applications, including DBMSs, utilizing cryptography are required to use approved NIST FIPS 140-2 or 140-3 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.  

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The standard for validating cryptographic modules will transition to the NIST FIPS 140-3 publication.

FIPS 140-2 modules can remain active for up to five years after validation or until September 21, 2026, when the FIPS 140-2 validations will be moved to the historical list. Even on the historical list, CMVP supports the purchase and use of these modules for existing systems. While Federal Agencies decide when they move to FIPS 140-3 only modules, purchasers are reminded that for several years there may be a limited selection of FIPS 140-3 modules from which to choose. CMVP recommends purchasers consider all modules that appear on the Validated Modules Search Page:
https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules

More information on the FIPS 140-3 transition can be found here: 
https://csrc.nist.gov/Projects/fips-140-3-transition-effort/

For more detailed information on Redis, refer to:
https://docs.redislabs.com/latest/rs/administering/designing-production/security/'
  desc 'check', 'Review the Redis Enterprise configuration to verify it is using NIST FIPS validated cryptographic modules for cryptographic operations. Redis Enterprise uses TLS 1.2 and has a cyber suite of options that is configurable through the rladmin, REST API, and on the Redis Enterprise web UI.

Verify the host operating system is encrypted. 

If the host operating system is not encrypted, this is a finding.

If the host operating system is encrypted, run the following commands and verify that only DoD-approved PKI certificates are present:
# cd /etc/opt/redislabs
# ls 

Verify the following file is present: proxy_cert.pem

If no certificates are present, this is a finding.

Verify TLS is configured to be used. To check this:
1. Log in to the Redis Enterprise web UI as an admin user.
2. Navigate to the Databases tab and select the database and then configuration.
3. Review the configuration and verify that TLS is enabled for all communications.

If TLS is not configured to be used, this is a finding.

To check the current TLS version, run the following commands on one of the servers that is hosting Redis Enterprise as a privileged user:
# ccs-cli
# hgetall min_control_tls_version

If TLS is not FIPS compliant, this is a finding.

To validate the openssl version, run the following command on one of the servers that is hosting Redis Enterprise as a privileged user:
# openssl version

If NIST FIPS validated modules are not being used for all cryptographic operations, this is a finding.'
  desc 'fix', 'Configure Redis Enterprise settings to use NIST FIPS 140-2-validated cryptographic modules for cryptographic operations. To set the minimum TLS version that can be used for encrypting the data in transit between a Redis client and a Redis Enterprise cluster, use the REST API or the following rladmin command:
rladmin> cluster config min_data_TLS_version <version> (e.g., 1.2)

Ensure that openssl is on the latest version as required by organizational policies to be FIPS compliant.'
  impact 0.7
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54664r863362_chk'
  tag severity: 'high'
  tag gid: 'V-251229'
  tag rid: 'SV-251229r863364_rule'
  tag stig_id: 'RD6X-00-009500'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-54618r863363_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
