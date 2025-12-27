control 'SV-238475' do
  title 'Database data files containing sensitive information must be encrypted.'
  desc "Cryptography is only as strong as the encryption modules/algorithms employed to encrypt the data. 

Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. 

Data files that are not encrypted are vulnerable to theft. When data files are not encrypted they can be copied and opened on a separate system. The data can be compromised without the information owner's knowledge that the theft has even taken place."
  desc 'check', 'Review the system documentation to determine whether the database handles classified information. If the database handles classified information, upgrade the severity Category Code to I.

Review the system documentation to discover sensitive or classified data identified by the Information Owner that requires encryption. If no sensitive or classified data is identified as requiring encryption by the Information Owner, this is not a finding.

Have the DBA use select statements in the database to review sensitive data stored in tables as identified in the system documentation.

If all sensitive data identified is encrypted within the database objects, encryption of the DBMS data files is optional and not a finding.

If all sensitive data is not encrypted within database objects, review encryption applied to the DBMS host data files. If no encryption is applied, this is a finding.'
  desc 'fix', "Obtain and utilize native or third-party NIST-validated FIPS 140-2-compliant cryptography solution for the DBMS.  Configure cryptographic functions to use FIPS 140-2-compliant algorithms and hashing functions.

Deploy Oracle 11.2.0.4 with the January 2014 CPU patch.

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

There is more information on this topic in the Oracle Database 11.2g Advanced Security Administrator's Guide, which may be found at  http://docs.oracle.com/cd/E11882_01/network.112/e40393.pdf

FIPS 140-2 can be downloaded from http://csrc.nist.gov/publications/PubsFIPS.html#140-2"
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41686r667597_chk'
  tag severity: 'medium'
  tag gid: 'V-238475'
  tag rid: 'SV-238475r667599_rule'
  tag stig_id: 'O112-C2-016700'
  tag gtitle: 'SRG-APP-000516-DB-000363'
  tag fix_id: 'F-41645r667598_fix'
  tag 'documentable'
  tag legacy: ['V-52311', 'SV-66527']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
