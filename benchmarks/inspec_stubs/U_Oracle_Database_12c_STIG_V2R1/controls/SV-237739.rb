control 'SV-237739' do
  title 'The DBMS must implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.'
  desc 'Use of cryptography to provide confidentiality and non-repudiation is not effective unless strong methods are employed. Many earlier encryption methods and modules have been broken and/or overtaken by increasing computing power. The NIST FIPS 140-2 cryptographic standards provide proven methods and strengths to employ cryptography effectively.

Detailed information on the NIST Cryptographic Module Validation Program (CMVP) is available at http://csrc.nist.gov/groups/STM/cmvp/index.html

Note: this does not require that all databases be encrypted. It specifies that if encryption is required, then the implementation of the encryption must satisfy the prevailing standards.'
  desc 'check', %q(If encryption is not required for the database, this is not a finding.

If the DBMS has not implemented federally required cryptographic protections for the level of classification of the data it contains, this is a finding.

Check the following settings to see if FIPS 140-2 encryption is configured. If encryption is not configured, check with the DBA and SYSTEM Administrator to see if other mechanisms or third-party products are deployed to encrypt data during the transmission or storage of data.

For Transparent Data Encryption and DBMS_CRYPTO:

To see if Oracle is configured for FIPS 140-2 Transparent Data Encryption and/or DBMS_CRYPTO, enter the following SQL*Plus command:
SHOW PARAMETER DBFIPS_140
or the following SQL query:
SELECT * FROM SYS.V$PARAMETER WHERE NAME = 'DBFIPS_140';

If Oracle returns the value 'FALSE', or returns no rows, this is a finding.

To see if Oracle is configured for FIPS 140-2 SSL/TLS authentication and/or Encryption:

Verify the DBMS version:
select * from V_$VERSION;

If the version displayed for Oracle Database is lower than 12.1.0.2, this is a finding.

If the operating system is Windows and the DBMS version is 12.1.0.2, use the opatch command to display the patches applied to the DBMS.

If the patches listed do not include "WINDOWS DB BUNDLE PATCH 12.1.0.2.7", this is a finding.

Open the fips.ora file in a browser or editor.  (The default location for fips.ora is $ORACLE_HOME/ldap/admin/ but alternate locations are possible. An alternate location, if it is in use, is specified in the FIPS_HOME environment variable.)

If the line "SSLFIPS_140=TRUE" is not found in fips.ora, or the file does not exist, this is a finding.

For (Native) Network Data Encryption:
If the line, SQLNET.FIPS_140=TRUE is not found in $ORACLE_HOME/network/admin/sqlnet.ora, this is a finding. (Note: This assumes that a single sqlnet.ora file, in the default location, is in use. Please see the supplemental file "Non-default sqlnet.ora configurations.pdf" for how to find multiple and/or differently located sqlnet.ora files.)

Note: For the Solaris platform, when DBFIPS_140 is FALSE, TDE (but not DBMS_CRYPTO) can still operate in a FIPS 140-compliant manner if FIPS 140 operation is enabled for the Solaris Cryptographic Framework.)
  desc 'fix', 'Implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

Where not already in effect, upgrade the DBMS to version 12.1.0.2 or higher.

Where the operating system is Windows and the DBMS version is 12.1.0.2, install patch "WINDOWS DB BUNDLE PATCH 12.1.0.2.7" if not already deployed.

Open the fips.ora file in an editor.  (The default location for fips.ora is $ORACLE_HOME/ldap/admin/ but alternate locations are possible. An alternate location, if it is in use, is specified in the FIPS_HOME environment variable.)

Create or modify fips.ora to include the line "SSLFIPS_140=TRUE".

- - - - -
The strength requirements are dependent upon data classification.

For unclassified data, where cryptography is required:
AES 128 for encryption
SHA 256 for hashing

NSA has established the suite B encryption requirements for protecting National Security Systems (NSS) as follows:
AES 128 for Secret
AES 256 for Top Secret
SHA 256 for Secret
SHA 384 for Top Secret

National Security System is defined as:
(OMB Circular A-130) Any telecommunications or information system operated by the United States Government, the function, operation, or use of which (1) involves intelligence activities; (2) involves cryptologic activities related to national security; (3) involves command and control of military forces; (4) involves equipment that is an integral part of a weapon or weapons system; or (5) is critical to the direct fulfillment of military or intelligence missions, but excluding any system that is to be used for routine administrative and business applications (including payroll, finance, logistics, and personnel management applications).'
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40958r667247_chk'
  tag severity: 'medium'
  tag gid: 'V-237739'
  tag rid: 'SV-237739r667249_rule'
  tag stig_id: 'O121-C2-016600'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-40921r667248_fix'
  tag 'documentable'
  tag legacy: ['V-61759', 'SV-76249']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
