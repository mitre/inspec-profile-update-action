control 'SV-75279' do
  title 'The Arista Multilayer Switch must uniquely identify all network-connected endpoint devices before establishing any connection.'
  desc 'Without identifying devices, unidentified or unknown devices may be introduced, thereby facilitating malicious activity.

For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of identification claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide the identification decisions (as opposed to the actual identifiers) to the services that need to act on those decisions.

This requirement applies to applications that connect either locally, remotely, or through a network to an endpoint device (including, but not limited to, workstations, printers, servers (outside a datacenter), VoIP Phones, and VTC CODECs). Gateways and SOA applications are examples of where this requirement would apply.'
  desc 'check', 'Verify that the network device uniquely identifies network-connected endpoint devices. This requirement is not applicable to Arista switches when not used as an access switch.

802.1X must be configured on any interface where there is an applicable endpoint device connected. This is demonstrated by viewing the running-config via the "show dot1x all" command and validating the following lines are present in the configuration:

Dot1X Information for Ethernet[X]
--------------------------------------------
PortControl : auto
HostMode : single-host
QuietPeriod : [value]
TxPeriod : [value]
ReauthPeriod : 3600 seconds
MaxReauthReq : 2

!

802.1X must also be globally enabled on the switch using the "dot1x system-auth-control" command from the configuration mode interface. When this is configured, the following line will be visible in the running-config:

dot1x-system-auth-control

802.1X is dependent on a properly configured RADIUS server for authentication. Refer to the RADIUS configuration example for validation of properly configured AAA services. Additionally, the user must specify to use the RADIUS server as an 802.1X authenticator with the "aaa authentication dot1x default group [radius]" command from the configuration mode interface, replacing the bracketed variable with either the group name of the RADIUS server group or leaving it as is to authenticate against all RADIUS servers. When properly configured, the following line is visible in the running-config:

aaa authentication dot1x default group radius

If 802.1X is not configured on necessary ports or is not globally enabled on the switch, or if it is not set to authenticate supplicants via RADIUS, this is a finding.'
  desc 'fix', 'Configure 802.1X on the switch, using the following mandatory parameters for all applicable interfaces. Replace the bracketed variable with the applicable value.

config
interface Ethernet[X]
 switchport access vlan [Y]
 dot1x pae authenticator
 dot1x reauthentication
 dot1x port-control auto
 dot1x host-mode single-host
 dot1x timeout quiet-period [value]
 dot1x timeout reauth-period [value]
 dot1x max-reauth-req [value]

For the global configuration, include the following command statements from the global configuration mode interface:

logging level DOT1X informational
aaa authentication dot1x default group radius
dot1x system-auth-control'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series L2S'
  tag check_id: 'C-61769r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60823'
  tag rid: 'SV-75279r1_rule'
  tag stig_id: 'AMLS-L2-000120'
  tag gtitle: 'SRG-NET-000148'
  tag fix_id: 'F-66533r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000778']
  tag nist: ['IA-3']
end
