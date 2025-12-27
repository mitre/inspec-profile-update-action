control 'SV-220294' do
  title 'The DBMS must use  NIST-validated FIPS 140-2-compliant cryptography for authentication mechanisms.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms.

Applications utilizing encryption are required to use approved encryption modules that meet the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

FIPS 140-2 is the current standard for validating cryptographic modules, and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified hardware-based encryption modules.

Authentication modules with weak encryption could allow an attacker to gain access to data stored in the database and to the administration settings of the DBMS.'
  desc 'check', 'Check the following settings to see if FIPS 140-2 authentication/encryption is configured. If encryption is required but not configured, check with the DBA and system administrator to see if other mechanisms or third-party cryptography products are deployed for authentication.

To see if Oracle is configured for FIPS 140-2 SSL/TLS authentication and/or Encryption:

Verify the DBMS version:
select * from V_$VERSION;
If the version displayed for Oracle Database is lower than 12.1.0.2, this is a finding.

If the operating system is Windows and the DBMS version is 12.1.0.2, use the opatch command to display the patches applied to the DBMS.

If the patches listed do not include "WINDOWS DB BUNDLE PATCH 12.1.0.2.7", this is a finding.

Open the fips.ora file in a browser or editor.  (The default location for fips.ora is $ORACLE_HOME/ldap/admin/ but alternate locations are possible. An alternate location, if it is in use, is specified in the FIPS_HOME environment variable.)

If the line "SSLFIPS_140=TRUE" is not found in fips.ora, or the file does not exist, this is a finding.'
  desc 'fix', %q(Utilize NIST-validated FIPS 140-2-compliant cryptography for all authentication mechanisms.

Where not already in effect, upgrade the DBMS to version 12.1.0.2 or higher.

Where the operating system is Windows and the DBMS version is 12.1.0.2, install patch "WINDOWS DB BUNDLE PATCH 12.1.0.2.7" if not already deployed.

Open the fips.ora file in an editor.  (The default location for fips.ora is $ORACLE_HOME/ldap/admin/ but alternate locations are possible. An alternate location, if it is in use, is specified in the FIPS_HOME environment variable.)
Create or modify fips.ora to include the line "SSLFIPS_140=TRUE".

- - - - -
The strength requirements are dependent upon data classification.

For unclassified data, where cryptography is required:
AES 128 for encryption
SHA 256 for hashing

NSA has established the suite B encryption requirements for protecting National Security Systems (NSS) as follows.
AES 128 for Secret
AES 256 for Top Secret
SHA 256 for Secret
SHA 384 for Top Secret

National Security System is defined as:
(OMB Circular A-130) Any telecommunications or information system operated by the United States Government, the function, operation, or use of which (1) involves intelligence activities; (2) involves cryptologic activities related to national security; (3) involves command and control of military forces; (4) involves equipment that is an integral part of a weapon or weapons system; or (5) is critical to the direct fulfillment of military or intelligence missions, but excluding any system that is to be used for routine administrative and business applications (including payroll, finance, logistics, and personnel management applications).

There is more information on this topic in the Oracle Database 12c Advanced Security Administrator's Guide, which may be found at https://docs.oracle.com/database/121/DBSEG/E48135-11.pdf. (Note, however, that because of changes in Oracle's licensing policy, it is no longer necessary to purchase Oracle Advanced Security to use network encryption and advanced authentication.)

FIPS 140-2 documentation can be downloaded from http://csrc.nist.gov/publications/PubsFIPS.html#140-2)
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-22009r392013_chk'
  tag severity: 'medium'
  tag gid: 'V-220294'
  tag rid: 'SV-220294r397606_rule'
  tag stig_id: 'O121-C2-015700'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-22001r392014_fix'
  tag 'documentable'
  tag legacy: ['SV-76237', 'V-61747']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
