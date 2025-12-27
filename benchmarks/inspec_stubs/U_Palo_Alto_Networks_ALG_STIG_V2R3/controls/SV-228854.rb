control 'SV-228854' do
  title 'The Palo Alto Networks security platform, if used as a TLS gateway/decryption point or VPN concentrator, must control remote access methods (inspect and filter traffic).'
  desc 'Remote access devices, such as those providing remote access to network devices and information systems, which lack automated control capabilities, increase risk and makes remote user access management difficult at best.

Remote access is access to DoD-nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include broadband and wireless connections. Remote access methods include, for example, proxied remote encrypted traffic (e.g., TLS gateways, web content filters, and webmail proxies).

If the Palo Alto Networks security platform is used as a TLS gateway/decryption point or VPN concentrator, configure the device to inspect and filter decrypted traffic. For each type of SSL/TLS traffic that is decrypted, the resulting traffic must be inspected and filtered.  For example, HTTPS traffic that is decrypted must have the HTTP traffic inspected and filtered.'
  desc 'check', 'If the Palo Alto Networks security platform is not used as a TLS gateway/decryption point or VPN concentrator, this is not applicable.

Go to Policies >> Decryption
Note each configured decryption policy.
Go to Policies >> Security
View the configured security policies.

If there is a decryption policy that does not have a corresponding security policy, this is a finding.
The matching policy may not be obvious, and it may be necessary for the Administrator to identify the corresponding security policy.'
  desc 'fix', 'These instructions explain the steps involved, but do not provide specific details since the exact policies and expected traffic are not known.

Go to Policies >> Security
Select "Add".
In the "Security Policy Rule" window, complete the required fields.
Configure the Security Policy in accordance with the policy for the resulting decrypted traffic.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks ALG'
  tag check_id: 'C-31089r513857_chk'
  tag severity: 'medium'
  tag gid: 'V-228854'
  tag rid: 'SV-228854r831594_rule'
  tag stig_id: 'PANW-AG-000078'
  tag gtitle: 'SRG-NET-000313-ALG-000010'
  tag fix_id: 'F-31066r513858_fix'
  tag 'documentable'
  tag legacy: ['V-62589', 'SV-77079']
  tag cci: ['CCI-002314']
  tag nist: ['AC-17 (1)']
end
