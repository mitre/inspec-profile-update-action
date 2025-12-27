control 'SV-243220' do
  title 'WLAN must use EAP-TLS.'
  desc 'EAP-TLS provides strong cryptographic mutual authentication and key distribution services not found in other EAP methods, and thus provides significantly more protection against attacks than other methods. 

Additionally, EAP-TLS supports two-factor user authentication on the WLAN client, which provides significantly more protection than methods that rely on a password or certificate alone. EAP-TLS also can leverage the DoD Common Access Card (CAC) in its authentication services, providing additional security and convenience.'
  desc 'check', 'Note: If the equipment is WPA2/WPA3 certified by the Wi-Fi Alliance, it is capable of supporting this requirement.

Review the WLAN equipment configuration to verify that EAP-TLS is actively used and no other methods are enabled.

If EAP-TLS is not used or if the WLAN system allows users to connect with other methods, this is a finding.'
  desc 'fix', 'Change the WLAN configuration so it supports EAP-TLS, implementing supporting PKI and AAA infrastructure as necessary. If the WLAN equipment is not capable of supporting EAP-TLS, procure new equipment capable of such support.'
  impact 0.5
  ref 'DPMS Target Network WLAN AP-NIPR Platform'
  tag check_id: 'C-46495r720113_chk'
  tag severity: 'medium'
  tag gid: 'V-243220'
  tag rid: 'SV-243220r720115_rule'
  tag stig_id: 'WLAN-NW-000500'
  tag gtitle: 'SRG-NET-000070'
  tag fix_id: 'F-46452r720114_fix'
  tag 'documentable'
  tag cci: ['CCI-001444']
  tag nist: ['AC-18 (1)']
end
