control 'SV-213603' do
  title 'The EDB Postgres Advanced Server must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of utilizing encryption and digital signatures to protect data. Weak algorithms can be easily broken and not validated cryptographic modules may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

Applications (including DBMSs) utilizing cryptography are required to use approved NIST FIPS 140-2 or 140-3 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The standard for validating cryptographic modules will transition to the NIST FIPS 140-3 publication.

FIPS 140-2 modules can remain active for up to five years after validation or until September 21, 2026, when the FIPS 140-2 validations will be moved to the historical list. Even on the historical list, CMVP supports the purchase and use of these modules for existing systems. While Federal Agencies decide when they move to FIPS 140-3 only modules, purchasers are reminded that for several years there may be a limited selection of FIPS 140-3 modules from which to choose. CMVP recommends purchasers consider all modules that appear on the Validated Modules Search Page:
https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules

More information on the FIPS 140-3 transition can be found here: 
https://csrc.nist.gov/Projects/fips-140-3-transition-effort/'
  desc 'check', 'If a FIPS-certified OpenSSL library is not installed and configured, this is a finding.

Run this command to ensure that you are running RHEL: "cat /etc/redhat-release"

Run this command to see the OpenSSL version: "openssl version"

If "/etc/redhat-release" does not show a supported version of Red Hat Enterprise Linux or if the openssl version does not include "-fips" in the version, this is a finding.'
  desc 'fix', 'Install PostgreSQL with FIPS-compliant cryptography enabled on an OS found in the CMVP (https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules) or by other means, ensure that FIPS 140-2 or 140-3 certified OpenSSL libraries are used by the DBMS.

FIPS documentation can be downloaded from https://csrc.nist.gov/publications/fips'
  impact 0.7
  ref 'DPMS Target EDB Postgres Advanced Server'
  tag check_id: 'C-14825r290121_chk'
  tag severity: 'high'
  tag gid: 'V-213603'
  tag rid: 'SV-213603r836843_rule'
  tag stig_id: 'PPS9-00-004900'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-14823r836842_fix'
  tag 'documentable'
  tag legacy: ['SV-83563', 'V-68959']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
