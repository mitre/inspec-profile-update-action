control 'SV-234668' do
  title 'The UEM server must be configured to implement FIPS 140-2 mode for all server and agent encryption.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session. 

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.

A block cipher mode is an algorithm that features the use of a symmetric key block cipher algorithm to provide an information service, such as confidentiality or authentication.

AES is the FIPS-validated cipher block cryptographic algorithm approved for use in DoD. For an algorithm implementation to be listed on a FIPS 140-2 cryptographic module validation certificate as an approved security function, the algorithm implementation must meet all the requirements of FIPS 140-2 and must successfully complete the cryptographic algorithm validation process. Currently, NIST has approved the following confidentiality modes to be used with approved block ciphers in a series of special publications: ECB, CBC, OFB, CFB, CTR, XTS-AES, FF1, FF3, CCM, GCM, KW, KWP, and TKW. 

Satisfies:FCS_COP.1.1(1), FTP_TRP.1.1(1)  
Reference:PP-MDM-414001'
  desc 'check', 'Verify FIPS 140-2 mode has been implemented on the UEM server for all server and agent encryption.

If FIPS 140-2 mode has not been implemented on the UEM server for all server and agent encryption, this is a finding.'
  desc 'fix', 'Configure the UEM server to implement FIPS 140-2 mode for all server and agent encryption.'
  impact 0.7
  ref 'DPMS Target Unified Endpoint Management Server'
  tag check_id: 'C-37853r615638_chk'
  tag severity: 'high'
  tag gid: 'V-234668'
  tag rid: 'SV-234668r879888_rule'
  tag stig_id: 'SRG-APP-000555-UEM-000393'
  tag gtitle: 'SRG-APP-000555'
  tag fix_id: 'F-37818r615639_fix'
  tag 'documentable'
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
