control 'SV-253960' do
  title 'The Juniper EX switch must be configured to enable IP Source Guard on all user-facing or untrusted access VLANs.'
  desc "IP Source Guard provides source IP address filtering on an untrusted layer 2 interface to prevent a malicious host from impersonating a legitimate host by assuming the legitimate host's IP address. The feature uses dynamic DHCP snooping and static IP source binding to match IP addresses to hosts on untrusted layer 2 access interfaces. Initially, all IP traffic on the protected interface is blocked except for DHCP packets. After a client receives an IP address from the DHCP server, or after static IP source binding is configured by the administrator, all traffic with that IP source address is permitted from that client. Traffic from other hosts is denied. This filtering limits a host's ability to attack the network by claiming a neighbor host's IP address."
  desc 'check', 'Review the switch configuration to verify that IP Source Guard is enabled on all user-facing or untrusted VLANs. Configuring IP Source Guard automatically enables DHCP snooping.

Devices like printers, servers, and VoIP phones are under enterprise control and connected to controlled access interfaces (802.1x, Static MAC Bypass, or MAC RADIUS), making them trusted sources in non-user-facing VLANs.

Verify IP Source Guard on user-facing or untrusted VLANs.
[edit vlans]
<untrusted VLAN name> {
    vlan-id <VLAN ID>;
    forwarding-options {
        dhcp-security {
            ip-source-guard;
        }
    }
}
Note: IP Source Guard depends upon DHCP snooping or static MAC address bindings.

If the switch does not have IP Source Guard enabled on all user-facing or untrusted VLANs, this is a finding.'
  desc 'fix', 'Configure the switch to have IP Source Guard enabled on all user-facing or untrusted VLANs.

set vlans <untrusted VLAN name> vlan-id <VLAN ID>
set vlans <untrusted VLAN name> forwarding-options dhcp-security ip-source-guard'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Layer 2 Switch'
  tag check_id: 'C-57412r843911_chk'
  tag severity: 'medium'
  tag gid: 'V-253960'
  tag rid: 'SV-253960r843913_rule'
  tag stig_id: 'JUEX-L2-000130'
  tag gtitle: 'SRG-NET-000362-L2S-000026'
  tag fix_id: 'F-57363r843912_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
