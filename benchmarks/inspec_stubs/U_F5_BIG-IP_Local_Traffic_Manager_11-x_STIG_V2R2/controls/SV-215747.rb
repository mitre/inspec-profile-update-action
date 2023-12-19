control 'SV-215747' do
  title 'The BIG-IP Core implementation must be configured to comply with the required TLS settings in NIST SP 800-52 Revision 1 for TLS services to virtual servers.'
  desc 'NIST SP 800-52 Revision 1 provides guidance on using the most secure version and configuration of the TLS/SSL protocol. Using older unauthorized versions or incorrectly configuring protocol negotiation makes the gateway vulnerable to known and unknown attacks that exploit vulnerabilities in this protocol.

This requirement applies to TLS gateways (also known as SSL gateways) and is not applicable to VPN devices. Application protocols such as HTTPS and DNSSEC use TLS/SSL as the underlying security protocol and thus are in scope for this requirement. NIST SP 800-52 Revision 1 provides guidance.

NIST SP 800-52 Revision 1 sets TLS version 1.1 as a minimum version, thus all versions of SSL are not allowed (including for client negotiation) either on DoD-only or on public facing servers.'
  desc 'check', 'If the BIG-IP Core does not provide intermediary services for TLS, or application protocols that use TLS (e.g., DNSSEC or HTTPS) for virtual servers, this is not applicable.

When intermediary services for TLS are provided, verify the BIG-IP Core is configured to implement the applicable required TLS settings in NIST PUB SP 800-52 Revision 1.

Navigate to the BIG-IP System manager >> Local Traffic >> Profiles >> SSL >> Client

Verify a profile exists that is FIPS compliant.

Select FIPS-compliant profile.

Select "Advanced" next to "Configuration".

Verify "Ciphers" under "Configuration" section is configured to use FIPS-compliant ciphers.

Verify the BIG-IP Core is configured to use FIPS-compliant server profile:

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Configuration" section, that the FIPS-compliant profile is in the "Selected" area for "SSL Profile (Client)".

If the BIG-IP Core is not configured to implement the applicable required TLS settings in NIST PUB SP 800-52 Revision 1, this is a finding.'
  desc 'fix', 'If intermediary services for TLS are provided, configure the BIG-IP Core to comply with applicable required TLS settings in NIST PUB SP 800-52 Revision 1.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16939r291054_chk'
  tag severity: 'medium'
  tag gid: 'V-215747'
  tag rid: 'SV-215747r557356_rule'
  tag stig_id: 'F5BI-LT-000035'
  tag gtitle: 'SRG-NET-000062-ALG-000150'
  tag fix_id: 'F-16937r291055_fix'
  tag 'documentable'
  tag legacy: ['V-60275', 'SV-74705']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
