control 'SV-237699' do
  title 'The DBMS must employ cryptographic mechanisms preventing the unauthorized disclosure of information during transmission unless the transmitted data is otherwise protected by alternative physical measures.'
  desc "Preventing the disclosure of transmitted information requires that applications take measures to employ some form of cryptographic mechanism in order to protect the information during transmission. This is usually achieved through the use of Transport Layer Security (TLS), SSL VPN, or IPSEC tunnel.

Alternative physical protection measures include Protected Distribution Systems (PDS). PDS are used to transmit unencrypted classified NSI through an area of lesser classification or control. Inasmuch as the classified NSI is unencrypted, the PDS must provide adequate electrical, electromagnetic, and physical safeguards to deter exploitation. Refer to NSTSSI No. 7003 for additional details on a PDS.

Information in transmission is particularly vulnerable to attack. If the DBMS does not employ cryptographic mechanisms preventing unauthorized disclosure of information during transit, the information may be compromised.

SHA-1 is in the process of being removed from service within the DoD and it's use is to be limited during the transition to SHA-2.  Use of SHA-1 for digital signature generation is prohibited.  Allowable uses during the transition include CHECKSUM usage and verification of legacy certificate signatures.  SHA-1 is considered a temporary solution during legacy application transitionary periods and should not be engineered into new applications. SHA-2 is the path forward for DoD."
  desc 'check', 'Check DBMS settings to determine whether cryptographic mechanisms are used to prevent the unauthorized disclosure of information during transmission. Determine whether physical measures are being used instead of cryptographic mechanisms. If neither cryptographic nor physical measures are being utilized, this is a finding.

To check that network encryption is enabled and using site-specified encryption procedures, look in SQLNET.ORA located at $ORACLE_HOME/network/admin/sqlnet.ora. (Note: This assumes that a single sqlnet.ora file, in the default location, is in use. Please see the supplemental file "Non-default sqlnet.ora configurations.pdf" for how to find multiple and/or differently located sqlnet.ora files.) If encryption is set, entries like the following will be present:

SQLNET.CRYPTO_CHECKSUM_TYPES_CLIENT= (SHA384)
SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER= (SHA384)
SQLNET.ENCRYPTION_TYPES_CLIENT= (AES256)

SQLNET.ENCRYPTION_TYPES_SERVER= (AES256)
SQLNET.CRYPTO_CHECKSUM_CLIENT = requested
SQLNET.CRYPTO_CHECKSUM_SERVER = required

(The values assigned to the parameters may be different, the combination of parameters may be different, and not all of the example parameters will necessarily exist in the file.)'
  desc 'fix', 'Configure DBMS and/or operating system to use cryptographic mechanisms to prevent unauthorized disclosure of information during transmission where physical measures are not being utilized.'
  impact 0.7
  ref 'DPMS Target Oracle Database 12c'
  tag check_id: 'C-40918r667127_chk'
  tag severity: 'high'
  tag gid: 'V-237699'
  tag rid: 'SV-237699r850688_rule'
  tag stig_id: 'O121-C1-019700'
  tag gtitle: 'SRG-APP-000441-DB-000378'
  tag fix_id: 'F-40881r667128_fix'
  tag 'documentable'
  tag legacy: ['V-61545', 'SV-76035']
  tag cci: ['CCI-002421']
  tag nist: ['SC-8 (1)']
end
