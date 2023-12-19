control 'SV-241657' do
  title 'tc Server ALL must validate client certificates, to include all intermediary CAs, to ensure the client-presented certificates are valid and that the entire trust chain is valid.  If PKI is not being used, this check is Not Applicable.'
  desc 'The DoD standard for authentication is DoD-approved PKI certificates. A certificate’s certification path is the path from the end entity certificate to a trusted root certification authority (CA). Certification path validation is necessary for a relying party to make an informed decision regarding acceptance of an end entity certificate. Certification path validation includes checks such as certificate issuer trust, time validity and revocation status for each certificate in the certification path. Revocation status information for CA and subject certificates in a certification path is commonly provided via certificate revocation lists (CRLs) or online certificate status protocol (OCSP) responses.'
  desc 'check', 'Obtain supporting documentation from the ISSO.

Review tc Server ALL configuration to verify that certificates being provided by the client are being validated in accordance with RFC 5280. If PKI is not being used, this is NA.

If certificates are not being validated in accordance with RFC 5280, this is a finding.'
  desc 'fix', 'Validate client certificates are being validated in accordance with RFC 5280.'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x tc Server'
  tag check_id: 'C-44933r684163_chk'
  tag severity: 'medium'
  tag gid: 'V-241657'
  tag rid: 'SV-241657r879612_rule'
  tag stig_id: 'VROM-TC-000460'
  tag gtitle: 'SRG-APP-000175-WSR-000095'
  tag fix_id: 'F-44892r683832_fix'
  tag 'documentable'
  tag legacy: ['SV-99599', 'V-88949']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
