control 'SV-214529' do
  title 'The Juniper SRX Services Gateway Firewall providing content filtering must protect against known and unknown types of Denial of Service (DoS) attacks by implementing statistics-based screens.'
  desc 'If the network does not provide safeguards against DoS attacks, network resources will be unavailable to users. Installation of content filtering gateways and application layer firewalls at key boundaries in the architecture mitigates the risk of DoS attacks. These attacks can be detected by matching observed communications traffic with patterns of known attacks and monitoring for anomalies in traffic volume/type.
 
Juniper SRX Firewall DoS protections can be configured by either using a Screen or within the global flow options. Screens, also known as IDS-options, block various layer 3 and 4 attacks. Screen objects are configured with various screen-specific options and then assigned to a zone. The Juniper SRX can be configured with Screens to protect against the following statistics-based DoS attacks: IP sweeps, port scans, and flood attacks.'
  desc 'check', 'Run the following command to see the screen options currently configured:

[edit]
show security screen ids-option
show security zone match "screen"

If security screens are not configured or if the security zone is not configured with screen options, this is a finding.'
  desc 'fix', 'The following example commands configure security screens under a profile named untrust-screen. Screen options, with configurable thresholds may be customized to minimize/prevent operational impact on traffic performance.

[edit]
set security screen ids-option <zone-name> <screen name> <option name> <value>

Based on 800-53 requirements and vendor recommendations, the following DoS screens are required, at a minimum, for use in DoD configurations.

set security screen ids-option untrust-screen icmp ip-sweep threshold 1000
set security screen ids-option untrust-screen tcp port-scan threshold 1000
set security screen ids-option untrust-screen tcp syn-flood alarm-threshold 1000
set security screen ids-option untrust-screen tcp syn-flood attack-threshold 1100
set security screen ids-option untrust-screen tcp syn-flood source-threshold 100
set security screen ids-option untrust-screen tcp syn-flood destination-threshold 2048
set security screen ids-option untrust-screen tcp syn-flood timeout 20
set security screen ids-option untrust-screen udp flood threshold 5000
set security screen ids-option untrust-screen udp udp-sweep threshold 1000

To enable screen protection, the screen profile must be associated with individual security zones using the following command. Recommend assigning "untrust-screen" profile name to the default zone named "untrust".

[edit]
set security zone security-zone <zone-name> screen <screen-profile>
Example: set security zones security-zone untrust screen untrust-screen'
  impact 0.7
  ref 'DPMS Target Juniper SRX Services Gateway ALG'
  tag check_id: 'C-15735r297271_chk'
  tag severity: 'high'
  tag gid: 'V-214529'
  tag rid: 'SV-214529r559708_rule'
  tag stig_id: 'JUSX-AG-000120'
  tag gtitle: 'SRG-NET-000362-ALG-000112'
  tag fix_id: 'F-15733r559707_fix'
  tag 'documentable'
  tag legacy: ['SV-80813', 'V-66323']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
