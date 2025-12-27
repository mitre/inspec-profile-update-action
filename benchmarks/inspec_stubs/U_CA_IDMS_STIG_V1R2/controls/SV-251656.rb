control 'SV-251656' do
  title 'CA IDMS must implement NIST FIPS 140-2 validated cryptographic modules to protect data-in-transit.'
  desc "Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The application must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

It is the responsibility of the data owner to assess the cryptography requirements in light of applicable federal laws, Executive Orders, directives, policies, regulations, and standards.

For detailed information, refer to NIST FIPS Publication 140-2, Security Requirements for Cryptographic Modules. Note that the product's cryptographic modules must be validated and certified by NIST as FIPS-compliant."
  desc 'check', 'Verify that connection to IDMS is FIPS-compliant.

1. For ODBC and JDBC Type 2 connections:   
   a. Configure the Data Source to enable the DTS-JCLI logging option.  
   b. Perform a connection test using the "Test" function on the administrator.
   c. View the generated log entries to determine the TLS version, cipher algorithm, and certificate employed.  

2020/04/27 09:51:41.946 P:0000502C T:00005DC8 JCLI Trace: SSL_connect(832) successful!
2020/04/27 09:51:41.946 P:0000502C T:00005DC8 JCLI Trace: SSL_connect(832) connection attempts: 1 
2020/04/27 09:51:41.947 P:0000502C T:00005DC8 JCLI Trace: SSL_connect(832) TLS version TLSv1.2 
2020/04/27 09:51:41.947 P:0000502C T:00005DC8 JCLI Trace: SSL_connect(832) cipher TLS_RSA_WITH_AES_256_CBC_SHA256 (this should  be one or more of the accepted ciphers)
                                                                                                                                                                                                                                                          Cipher Specifications
                                                                                                                                                                                                                                                          3DES_SHA
                                                                                                                                                                                                                                                          AES_256_SHA
                                                                                                                                                                                                                                                          AES_128_SHA
If connection is not verified this is a finding.

2. For all connection types:  IBM provides configuration options for multiple SSL components, to force FIPS-140 compliance.   
    a. System SSL:  The environment variable GSK_FIPS_STATE specifies GSK_FIPS_STATE_ON in the envar file in the GSKSRVR home directory or message "GSK01057I SSL server starting in FIPS mode" is in the JES
        log.
    b. ICFS: Review the JES log for the ICSF region for the following message is issued on startup 
         CSFM015I FIPS 140 SELF CHECKS FOR PKCS11 SERVICES SUCCESSFUL.

If either of the above is true this is not a finding.
If none of the above is true this is a finding.'
  desc 'fix', "Contact the appropriate system administrators to make the needed changes to allow the use of AT-TLS and the associated software.
See Broadcom Techdocs for further information:      
- Configure Secure Sockets
See IBM's z/OS Communications Server bookshelf for information on:  
- Configuring AT-TLS
See IBM's z/OS Cryptographic Services System bookshelf for information on 
- Algorithms and key sizes
- System SSL 
- ICSF Services"
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55094r807842_chk'
  tag severity: 'medium'
  tag gid: 'V-251656'
  tag rid: 'SV-251656r860658_rule'
  tag stig_id: 'IDMS-DB-000950'
  tag gtitle: 'SRG-APP-000514-DB-000383'
  tag fix_id: 'F-55048r807843_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
