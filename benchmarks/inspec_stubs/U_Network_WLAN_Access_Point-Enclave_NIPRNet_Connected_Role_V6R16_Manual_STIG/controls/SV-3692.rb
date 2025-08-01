control 'SV-3692' do
  title 'WLAN must use EAP-TLS.'
  desc 'EAP-TLS provides strong cryptographic mutual authentication and key distribution services not found in other EAP methods, and thus provides significantly more protection against attacks than other methods. Additionally, EAP-TLS supports two-factor user authentication on the WLAN client, which provides significantly more protection than methods that rely on a password or certificate alone. EAP-TLS also can leverage DoD CAC in its authentication services, providing additional security and convenience.'
  desc 'check', 'Note: If the equipment is WPA2/WPA3 certified, then it is capable of supporting this requirement.

Review the WLAN equipment configuration to check EAP-TLS is actively used and no other methods are enabled.

If EAP-TLS is not used or if the WLAN system allows users to connect with other methods, this is a finding.'
  desc 'fix', 'Change the WLAN configuration so it supports EAP-TLS, implementing supporting PKI and AAA infrastructure as necessary. If the WLAN equipment is not capable of supporting EAP-TLS, procure new equipment capable of such support.'
  impact 0.5
  ref 'DPMS Target Wireless Access Point'
  tag check_id: 'C-16042r4_chk'
  tag severity: 'medium'
  tag gid: 'V-3692'
  tag rid: 'SV-3692r3_rule'
  tag stig_id: 'WIR0115-01'
  tag gtitle: 'WLAN EAP authentication'
  tag fix_id: 'F-34114r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
end
