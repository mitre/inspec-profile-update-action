control 'SV-234134' do
  title 'The FortiGate firewall must use organization-defined filtering rules that apply to the monitoring of remote access traffic for the traffic from the VPN access points.'
  desc 'Remote access devices (such as those providing remote access to network devices and information systems) that lack automated capabilities increase risk and make remote user access management difficult at best.

Remote access is access to DoD non-public information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network.

Automated monitoring of remote access sessions allows organizations to detect cyberattacks and ensure ongoing compliance with remote access policies by auditing connection activities of remote access capabilities from a variety of information system components (e.g., servers, workstations, notebook computers, smart phones, and tablets).'
  desc 'check', 'If FortiGate is not configured to support VPN access, this requirement is Not Applicable.

Log in to the FortiGate GUI with Super- or Firewall Policy-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Verify all VPN-related policies are configured with organization-defined filtering rules.
4. For each VPN-related policy, verify the logging option is configured to log All Sessions (for most verbose logging).

If there are no VPN policies configured with organization-defined filtering rules, this is a finding.'
  desc 'fix', 'This fix can be performed on the FortiGate GUI or on the CLI. 
Log in to the FortiGate GUI with Super- or Firewall Policy-Admin privilege.

1. Click Policy and Objects.
2. Click IPv4 or IPv6 Policy.
3. Click +Create New to configure new ingress and egress SSL-VPN- or IPSec-VPN-related policies that meet the organization-defined filtering rules.
4. Configure Logging Options to log All Sessions (for most verbose logging).
5. Confirm each created Policy is Enabled.
6. Click OK.

or

1. Open a CLI console, via SSH or available from the GUI.
2. Run the following command:
     # config firewall policy
     #   edit 0
     #        set srcintf {vpn_interface}
     #        set dstintf {interface_1}
     #        set srcaddr {address_a}
     #        set dstaddr {address_b}
     #        set schedule {always}
     #        set service {services required by site policy}
     #        set action {accept}
     #        set logtraffic enable
     #    next
     # end
3. Create opposite (ingress or egress) policy as required.

The {} indicate the object is defined by the organization policy.'
  impact 0.5
  ref 'DPMS Target Fortinet FortiGate Firewall'
  tag check_id: 'C-37319r611400_chk'
  tag severity: 'medium'
  tag gid: 'V-234134'
  tag rid: 'SV-234134r611402_rule'
  tag stig_id: 'FNFG-FW-000015'
  tag gtitle: 'SRG-NET-000061-FW-000001'
  tag fix_id: 'F-37284r611401_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
end
