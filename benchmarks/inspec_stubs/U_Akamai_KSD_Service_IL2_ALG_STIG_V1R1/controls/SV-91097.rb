control 'SV-91097' do
  title 'Kona Site Defender that provides intermediary services for TLS must be configured to comply with the required TLS settings in NIST SP 800-52.'
  desc 'NIST SP 800-52 provides guidance on using the most secure version and configuration of the TLS/SSL protocol. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to TLS gateways (also known as SSL gateways) and is not applicable to VPN devices. Application protocols such as HTTPS and DNSSEC use TLS as the underlying security protocol and therefore are in scope for this requirement. NIST SP 800-52 provides guidance.

NIST SP 800-52 sets TLS version 1.1 as a minimum version; thus, no versions of SSL are allowed (including for client negotiation) on either DoD only or public-facing servers.'
  desc 'check', 'Confirm Kona Site Defender allows only NIST SP 800-52 TLS settings:

1. Navigate to the Qualys SSL Scanner: https://www.ssllabs.com/ssltest/analyze.html
2. Enter into the scanner the Hostname being tested.
3. Under the "Configurations" and then "Protocol" section, verify that communications are restricted to TLS versions 1.2 and above for government-only services or TLS versions 1.0 and above for citizen or business-facing applications.

If Kona Site Defender does not allow only NIST SP 800-52 TLS settings, this is a finding.'
  desc 'fix', 'Configure Kona Site Defender to only allow NIST SP 800-52 TLS settings:

Contact the Akamai Professional Services team to implement the changes at 1-877-4-AKATEC (1-877-425-2832).'
  impact 0.7
  ref 'DPMS Target Akamai Edge Security ALG'
  tag check_id: 'C-76057r1_chk'
  tag severity: 'high'
  tag gid: 'V-76401'
  tag rid: 'SV-91097r1_rule'
  tag stig_id: 'AKSD-WF-000007'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag fix_id: 'F-83077r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
