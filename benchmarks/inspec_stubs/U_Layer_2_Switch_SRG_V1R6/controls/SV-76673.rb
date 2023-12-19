control 'SV-76673' do
  title 'The layer 2 switch must have IP Source Guard enabled on all user-facing or untrusted access switch ports.'
  desc "IP Source Guard provides source IP address filtering on a Layer 2 port to prevent a malicious host from impersonating a legitimate host by assuming the legitimate host's IP address. The feature uses dynamic DHCP snooping and static IP source binding to match IP addresses to hosts on untrusted Layer 2 access ports. Initially, all IP traffic on the protected port is blocked except for DHCP packets. After a client receives an IP address from the DHCP server, or after static IP source binding is configured by the administrator, all traffic with that IP source address is permitted from that client. Traffic from other hosts is denied. This filtering limits a host's ability to attack the network by claiming a neighbor host's IP address."
  desc 'check', 'Review the switch configuration to verify that IP Source Guard is enabled on all user-facing or untrusted access switch ports.

If the switch does not have IP Source Guard enabled on all untrusted access switch ports, this is a finding.'
  desc 'fix', 'Configure the switch to have IP Source Guard enabled on all user-facing or untrusted access switch ports.'
  impact 0.5
  ref 'DPMS Target SRG-NET-L2S'
  tag check_id: 'C-62987r2_chk'
  tag severity: 'medium'
  tag gid: 'V-62183'
  tag rid: 'SV-76673r1_rule'
  tag stig_id: 'SRG-NET-000362-L2S-000026'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-68103r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
