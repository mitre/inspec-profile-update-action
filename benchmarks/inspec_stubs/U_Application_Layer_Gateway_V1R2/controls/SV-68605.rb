control 'SV-68605' do
  title 'The ALG that provides intermediary services for TLS must be configured to comply with the required TLS settings in NIST SP 800-52.'
  desc 'SP 800-52 provides guidance on using the most secure version and configuration of the TLS/SSL protocol. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks which exploit vulnerabilities in this protocol.

This requirement applies to TLS gateways (also known as SSL gateways) and is not applicable to VPN devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol thus are in scope for this requirement. NIS SP 800-52 provides guidance.

SP 800-52 sets TLS version 1.1 as a minimum version, thus all versions of SSL are not allowed (including for client negotiation) either on DoD-only or on public facing servers.'
  desc 'check', 'If the ALG does not provide intermediary services for TLS, or application protocols that use TLS (e.g., DNSSEC or HTTPS), this is not applicable.

Verify the ALG is configured to implement the applicable required TLS settings in NIST PUB SP 800-52.

If the ALG is not configured to implement the applicable required TLS settings in NIST PUB SP 800-52, this is a finding.'
  desc 'fix', 'If intermediary services for TLS are provided, configure the ALG to comply with applicable required TLS settings in NIST PUB SP 800-52.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-54975r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54359'
  tag rid: 'SV-68605r1_rule'
  tag stig_id: 'SRG-NET-000062-ALG-000150'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag fix_id: 'F-59213r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
