control 'SV-220368' do
  title 'MarkLogic Server must use NIST FIPS 140-2 or 140-3 validated cryptographic modules for cryptographic operations and protect classified information in accordance with the requirements of the data owner.'
  desc 'Use of weak or not validated cryptographic algorithms undermines the purposes of using encryption and digital signatures to protect data. Weak algorithms can be easily broken, and cryptographic modules that are not validated may not implement algorithms correctly. Unapproved cryptographic modules or algorithms should not be relied on for authentication, confidentiality, or integrity. Weak cryptography could allow an attacker to gain access to and modify data stored in the database as well as the administration settings of the DBMS.

Applications, including DBMSs, using cryptography are required to use approved NIST FIPS 140-2 or 140-3 validated cryptographic modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance. 

NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified, hardware-based encryption modules.

The standard for validating cryptographic modules will transition to the NIST FIPS 140-3 publication.

FIPS 140-2 modules can remain active for up to five years after validation or until September 21, 2026, when the FIPS 140-2 validations will be moved to the historical list. Even on the historical list, CMVP supports the purchase and use of these modules for existing systems. While Federal Agencies decide when they move to FIPS 140-3 only modules, purchasers are reminded that for several years there may be a limited selection of FIPS 140-3 modules from which to choose. CMVP recommends purchasers consider all modules that appear on the Validated Modules Search Page:
https://csrc.nist.gov/projects/cryptographic-module-validation-program/validated-modules

More information on the FIPS 140-3 transition can be found here: 
https://csrc.nist.gov/Projects/fips-140-3-transition-effort/

'
  desc 'check', 'Review MarkLogic configuration to determine whether SSL FIPS has been enabled.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Clusters icon.
2. In the Summary tab, if the value for "ssl fips enabled" is "false", this is a finding.'
  desc 'fix', 'Ensure SSL FIPS has been enabled in MarkLogic server.

Perform the fix operation from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Clusters icon.
2. Click the Configure tab.
3. Set the value for "ssl fips enabled" to "true" and click OK.'
  impact 0.7
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22083r401555_chk'
  tag severity: 'high'
  tag gid: 'V-220368'
  tag rid: 'SV-220368r863306_rule'
  tag stig_id: 'ML09-00-004300'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-22072r401556_fix'
  tag satisfies: ['SRG-APP-000179-DB-000114', 'SRG-APP-000416-DB-000380']
  tag 'documentable'
  tag legacy: ['SV-110085', 'V-100981']
  tag cci: ['CCI-000803', 'CCI-002450']
  tag nist: ['IA-7', 'SC-13 b']
end
