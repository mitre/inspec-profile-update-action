control 'SV-215799' do
  title 'The BIG-IP Core implementation must be configured to implement NIST FIPS-validated cryptography for digital signatures when providing encrypted traffic to virtual servers.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The network element must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

This requirement applies only to ALGs that provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC).'
  desc 'check', 'If the BIG-IP Core does not provide encryption intermediary services (e.g., HTTPS, TLS, or DNSSEC) for virtual servers, this is not applicable.

When encryption intermediary services are provided, verify the BIG-IP Core is configured to implement NIST FIPS-validated cryptography for digital signatures.

Navigate to the BIG-IP System manager >> Local traffic >> Profiles >> SSL >> Client.

Verify a profile exists that is FIPS Compliant.

Select a FIPS-compliant profile.

Select "Advanced" next to "Configuration".

Verify "Ciphers" under "Configuration" section is configured to use FIPS-compliant ciphers.

Verify applicable virtual servers are configured in the BIG-IP LTM to use a FIPS-compliant client profile:

Navigate to the BIG-IP System manager >> Local Traffic >> Virtual Servers >> Virtual Servers List tab.

Select Virtual Servers(s) from the list to verify.

Verify under "Configuration" section, that a FIPS-compliant profile is in the "Selected" area of "SSL Profile (Client)".

If the BIG-IP Core does not implement NIST FIPS-validated cryptography for digital signatures, this is a finding.'
  desc 'fix', 'If encryption intermediary services are provided, configure the BIG-IP Core to implement NIST FIPS-validated cryptography for digital signatures.'
  impact 0.5
  ref 'DPMS Target F5 BIG-IP Local Traffic Manager 11.x'
  tag check_id: 'C-16991r291210_chk'
  tag severity: 'medium'
  tag gid: 'V-215799'
  tag rid: 'SV-215799r557356_rule'
  tag stig_id: 'F5BI-LT-000293'
  tag gtitle: 'SRG-NET-000510-ALG-000040'
  tag fix_id: 'F-16989r291211_fix'
  tag 'documentable'
  tag legacy: ['V-60379', 'SV-74809']
  tag cci: ['CCI-002450']
  tag nist: ['SC-13 b']
end
