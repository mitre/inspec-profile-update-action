control 'SV-3515' do
  title 'The WLAN must use AES-CCMP to protect data-in-transit.'
  desc 'AES-CCMP provides all required WLAN security services for data in transit. The other encryption protocol available for IEEE 802.11i compliant robust security networks and WPA2 certified solutions is the Temporal Key Integrity Protocol (TKIP). TKIP relies on the RC4 cipher, which has known vulnerabilities. Some WLANs also rely on Wireless Equivalent Privacy (WEP), which also uses RC4, and is easily cracked in minutes on active WLANs. Use of protocols other than AES-CCMP places DoD WLANs at greater risk of security breaches than other available approaches.'
  desc 'check', 'Detailed Policy requirements:

Encryption requirements for data in transit: 
- The WLAN infrastructure (e.g., access point, bridge, or WLAN controller) and WLAN client device must be configured to use the AES-CCMP encryption protocol.

Check procedures:
- Interview IAO and review WLAN system documentation.
- Determine if the WLAN network and client components encryption setting has been configured to use the AES-CCMP encryption protocol and no others. 
- Mark as a finding if the WLAN is configured to support any encryption protocol other than AES-CCMP, even if AES-CCMP is one of several supported options.'
  desc 'fix', 'Implement AES-CCMP to protect data in transit. Deactivate encryption protocols other than AES-CCMP.'
  impact 0.5
  ref 'DPMS Target Wireless Client'
  tag check_id: 'C-22364r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3515'
  tag rid: 'SV-3515r2_rule'
  tag stig_id: 'WIR0125-01'
  tag gtitle: 'Transmitted WLAN AES-CCMP'
  tag fix_id: 'F-3446r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECSC-1, ECWN-1'
end
