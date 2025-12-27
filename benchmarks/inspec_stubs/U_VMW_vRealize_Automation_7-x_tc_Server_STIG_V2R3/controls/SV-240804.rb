control 'SV-240804' do
  title 'tc Server ALL must validate client certificates, to include all intermediary CAs, to ensure the client-presented certificates are valid and that the entire trust chain is valid.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates. A certificate’s certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.'
  desc 'check', 'If PKI is not being used, this check is Not Applicable.

Interview the ISSO.

Review tc Server ALL configuration to verify that certificates being provided by the client are being validated in accordance with RFC 5280.

If certificates are not being validated in accordance with RFC 5280, this is a finding.'
  desc 'fix', 'If PKI is not being used, this check is Not Applicable.

Validate client certificates in accordance with RFC 5280.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x tc Server'
  tag check_id: 'C-44037r674433_chk'
  tag severity: 'medium'
  tag gid: 'V-240804'
  tag rid: 'SV-240804r879612_rule'
  tag stig_id: 'VRAU-TC-000445'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-43996r674155_fix'
  tag 'documentable'
  tag legacy: ['SV-100691', 'V-90041']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
