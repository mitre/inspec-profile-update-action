control 'SV-237740' do
  title 'Database data files containing sensitive information must be encrypted.'
  desc "Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data.

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data.

Data files that are not encrypted are vulnerable to theft. When data files are not encrypted they can be copied and opened on a separate system. The data can be compromised without the information owner's knowledge that the theft has even taken place."
  desc 'check', "If the database does not handle sensitive information, this is not a finding.

Review the system documentation to determine whether the database handles classified information. If the database handles classified information, upgrade the severity Category Code to I.

Review the system documentation to discover sensitive or classified data identified by the Information Owner that requires encryption.

If no sensitive or classified data is identified as requiring encryption by the Information Owner, this is not a finding.

Have the DBA use select statements in the database to review sensitive data stored in tables as identified in the system documentation.
To see if Oracle is configured for FIPS 140 Transparent Data Encryption and/or DBMS_CRYPTO, enter the following SQL*Plus command:

SHOW PARAMETER DBFIPS_140

or the following SQL query:

SELECT * FROM SYS.V$PARAMETER WHERE NAME = 'DBFIPS_140';

If Oracle returns the value 'FALSE', or returns no rows, this is a finding.

To see if there are encrypted tablespaces, enter the following SQL*Plus command:

SELECT * FROM V$ENCRYPTED_TABLESPACES;

If no rows are returned, then there are no encrypted tablespaces.

To see if there are encrypted columns within existing tables, enter the following SQL*Plus command:

SELECT * FROM DBA_ENCRYPTED_COLUMNS;

If no rows are returned, then there are no encrypted columns within existing tables.

If all sensitive data identified is encrypted within the database objects, encryption of the DBMS data files is optional and not a finding.

If all sensitive data is not encrypted within database objects, review encryption applied to the DBMS host data files. If no encryption is applied, this is a finding."
  desc 'fix', "Obtain and utilize native or third-party NIST-validated FIPS 140-2 or 140-3 compliant cryptography solution for the DBMS. Configure cryptographic functions to use FIPS 140 compliant algorithms and hashing functions.

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

There is more information on this topic in the Oracle Database 12c Advanced Security Administrator's Guide, which may be found at https://docs.oracle.com/database/121/ASOAG/toc.htm. (Note, however, that because of changes in Oracle's licensing policy, it is no longer necessary to purchase Oracle Advanced Security to use network encryption and advanced authentication.)

FIPS documentation can be downloaded from https://csrc.nist.gov/publications/fips"
  impact 0.5
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40959r836910_chk'
  tag severity: 'medium'
  tag gid: 'V-237740'
  tag rid: 'SV-237740r879887_rule'
  tag stig_id: 'O121-C2-016700'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-40922r836911_fix'
  tag 'documentable'
  tag legacy: ['V-61761', 'SV-76251']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
