control 'SV-206765' do
  title 'When using PKI-based authentication, the Voice Video Endpoint used for videoconferencing must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.'
  desc 'Without path validation, an informed trust decision by the relying party cannot be made when presented with any certificate not already explicitly trusted. A trust anchor is an authoritative entity represented via a public key. Within a chain of trust, the top entity to be trusted is the "root certificate" or "trust anchors" such as a Certification Authority (CA). A certification path starts with the subject certificate and proceeds through a number of intermediate certificates up to a trusted root certificate, typically issued by a trusted CA. 

This requirement verifies that a certification path to an accepted trust anchor is used for certificate validation and that the path includes status information. Path validation is necessary for a relying party to make an informed trust decision when presented with any certificate not already explicitly trusted. Status information for certification paths includes certificate revocation lists or online certificate status protocol responses. Validation of the certificate status information is out of scope for this requirement.'
  desc 'check', 'Verify the Voice Video Endpoint used for videoconferencing, when using PKI-based authentication, validates certificates by constructing a certification path to an accepted trust anchor. The constructed certification path must include status information. 

If the Voice Video Endpoint used for videoconferencing, when using PKI-based authentication, does not validate certificates by constructing a certification path that includes status information to an accepted trust anchor, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint used for videoconferencing, when using PKI-based authentication, to validate certificates by constructing a certification path, including status information, to an accepted trust anchor.'
  impact 0.7
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7021r363818_chk'
  tag severity: 'high'
  tag gid: 'V-206765'
  tag rid: 'SV-206765r604140_rule'
  tag stig_id: 'SRG-NET-000164-VVEP-00035'
  tag gtitle: 'SRG-NET-000164'
  tag fix_id: 'F-7021r363819_fix'
  tag 'documentable'
  tag legacy: ['SV-81243', 'V-66753']
  tag cci: ['CCI-000185']
  tag nist: ['IA-5 (2) (b) (1)']
end
