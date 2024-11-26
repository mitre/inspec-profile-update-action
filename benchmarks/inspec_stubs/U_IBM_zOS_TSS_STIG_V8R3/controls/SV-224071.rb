control 'SV-224071' do
  title 'IBM z/OS TELNETPARMS or TELNETGLOBALS must specify a SECUREPORT statement for systems requiring confidentiality and integrity.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during preparation for transmission, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

Ensuring the confidentiality of transmitted information requires the operating system to take measures in preparing information for transmission. This can be accomplished via access control and encryption.

Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. When transmitting data, operating systems need to support transmission protection mechanisms such as TLS, SSL VPNs, or IPsec.

'
  desc 'check', 'Refer to the Profile configuration file specified on the PROFILE DD statement in the TCPIP started task JCL.

If the following items are in effect for the configuration specified in the TCP/IP Profile configuration file, this is not a finding.

NOTE: If an INCLUDE statement is coded in the TCP/IP Profile configuration file, the data set specified on this statement must be checked for the following items as well.

NOTE: FIPS 140-2 minimum encryption is the accepted level of encryption and will override this requirement if greater.

-The TELNETGLOBALS block that specifies an ENCRYPTION statement states one or more of the below cipher specifications.
-Each TELNETPARMS block that specifies the SECUREPORT statement, specifies an ENCRYPTION statement states one or more of the below cipher specifications. And the TELNETGLOBALS block does or does not specify an ENCRYPTION statement.

Cipher Specifications
SSL_3DES_SHA
SSL_AES_256_SHA
SSL_AES_128_SHA'
  desc 'fix', 'Configure the SECUREPORT and TELNETPARMS ENCRYPTION statements and/or the TELNETGLOBALS statement in the PROFILE.TCPIP file to conform to the requirements specified below.

The TELNETGLOBALS block may specify an ENCRYPTION statement that specifies one or more of the below cipher specifications.

Each TELNETPARMS block that specifies the SECUREPORT statement, an ENCRYPTION statement is coded with one or more of the below cipher specifications. And the TELNETGLOBALS block does or does not specify an ENCRYPTION statement.

To prevent the use of non FIPS 140-2 encryption, the TELNETGLOBALS block and/or each TELNETPARMS block that specifies an ENCRYPTION statement will specify one or more of the following cipher specifications:

Cipher Specifications
SSL_3DES_SHA
SSL_AES_256_SHA
SSL_AES_128_SHA

Note: Always check for the minimum allowed in FIPS 140-2.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25744r516612_chk'
  tag severity: 'medium'
  tag gid: 'V-224071'
  tag rid: 'SV-224071r561402_rule'
  tag stig_id: 'TSS0-TN-000070'
  tag gtitle: 'SRG-OS-000425-GPOS-00189'
  tag fix_id: 'F-25732r516613_fix'
  tag satisfies: ['SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190']
  tag 'documentable'
  tag legacy: ['SV-107953', 'V-98849']
  tag cci: ['CCI-002420', 'CCI-002422']
  tag nist: ['SC-8 (2)', 'SC-8 (2)']
end
