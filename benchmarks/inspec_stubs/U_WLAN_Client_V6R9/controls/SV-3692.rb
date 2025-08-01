control 'SV-3692' do
  title 'WLAN must use EAP-TLS.'
  desc 'EAP-TLS provides strong cryptographic mutual authentication and key distribution services not found in other EAP methods, and thus provides significantly more protection against attacks than other methods. Additionally, EAP-TLS supports two-factor user authentication on the WLAN client, which provides significantly more protection than methods that rely on a password or certificate alone. EAP-TLS also can leverage DoD CAC in its authentication services, providing additional security and convenience.'
  desc 'check', 'NOTE: If the equipment is WPA2 certified, then it is capable of supporting this requirement.

Review the WLAN equipment configuration to check EAP-TLS is actively used and no other methods are enabled. 
Mark as a finding if either EAP-TLS is not used or if the WLAN system allows users to connect with other methods.

Note:  DoDI 8420.01 provides the capability for the DAA to grant limited exceptions to this requirement.'
  desc 'fix', 'Change the WLAN configuration so it supports EAP-TLS, implementing supporting PKI and AAA infrastructure as necessary. If the WLAN equipment is not capable of supporting EAP-TLS, procure new equipment capable of such support.'
  impact 0.5
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-16042r3_chk'
  tag severity: 'medium'
  tag gid: 'V-3692'
  tag rid: 'SV-3692r2_rule'
  tag stig_id: 'WIR0115-01'
  tag gtitle: 'WLAN EAP authentication'
  tag fix_id: 'F-34114r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag ia_controls: 'ECSC-1, ECWN-1'
end
