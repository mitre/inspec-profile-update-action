control 'SV-238474' do
  title 'The DBMS must implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.'
  desc 'Use of cryptography to provide confidentiality and non-repudiation is not effective unless strong methods are employed. Many earlier encryption methods and modules have been broken and/or overtaken by increasing computing power. The NIST FIPS 140-2 cryptographic standards provide proven methods and strengths to employ cryptography effectively.

Detailed information on the NIST Cryptographic Module Validation Program (CMVP) is available at http://csrc.nist.gov/groups/STM/cmvp/index.html.

Note:  this does not require that all databases be encrypted.  It specifies that if encryption is required, then the implementation of the encryption must satisfy the prevailing standards.'
  desc 'check', 'If encryption is not required for the database, this is not a finding.

If the DBMS has not implemented federally required cryptographic protections for the level of classification of the data it contains, this is a finding.

Determine whether the Oracle DBMS software is at version 11.2.0.4 with the January 2014 CPU (or above).  If it is not, this is a finding.'
  desc 'fix', "Implement required cryptographic protections using cryptographic modules complying with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

Deploy Oracle 11.2.0.4, with the January 2014 CPU patch, or a later version.  Configure cryptographic functions to use FIPS 140-2 compliant algorithms and hashing functions.

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
(OMB Circular A-130) Any telecommunications or information system operated by the United States Government, the function, operation, or use of which (1) involves intelligence activities; (2) involves cryptologic activities related to national security; (3) involves command and control of military forces; (4) involves equipment that is an integral part of a weapon or weapons system; or (5) is critical to the direct fulfillment of military or intelligence missions, but excluding any system that is to be used for routine administrative and business applications (including payroll, finance, logistics, and personnel management applications).

There is more information on this topic in the Oracle Database 11.2g Advanced Security Administrator's Guide, which may be found at  http://docs.oracle.com/cd/E11882_01/network.112/e40393.pdf.

FIPS 140-2 can be downloaded from http://csrc.nist.gov/publications/PubsFIPS.html#140-2"
  impact 0.5
  ref 'DPMS Target Oracle Database 11.2g'
  tag check_id: 'C-41685r667594_chk'
  tag severity: 'medium'
  tag gid: 'V-238474'
  tag rid: 'SV-238474r667596_rule'
  tag stig_id: 'O112-C2-016600'
  tag gtitle: 'SRG-APP-000179-DB-000114'
  tag fix_id: 'F-41644r667595_fix'
  tag 'documentable'
  tag legacy: ['V-52309', 'SV-66525']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
