control 'SV-251732' do
  title 'The NSX-T Distributed Firewall must configure SpoofGuard to block outbound IP packets that contain illegitimate packet attributes.'
  desc %q(SpoofGuard helps prevent a form of malicious attack called "web spoofing" or "phishing." A SpoofGuard policy blocks traffic determined to be spoofed.

SpoofGuard is a tool that is designed to prevent virtual machines in your environment from sending traffic with an IP address from which it is not authorized to send traffic. In the instance that a virtual machine's IP address does not match the IP address on the corresponding logical port and segment address binding in SpoofGuard, the virtual machine's vNIC is prevented from accessing the network entirely. SpoofGuard can be configured at the port or segment level. There are several reasons SpoofGuard might be used in your environment, but for the distributed firewall it will guarantee that rules will not be inadvertently (or deliberately) bypassed. For DFW rules created utilizing IP sets as sources or destinations, the possibility always exists that a virtual machine could have its IP address forged in the packet header, thereby bypassing the rules in question.)
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Segments, and for each Segment, view Segment Profiles >> SpoofGuard.

If a Segment is not configured with a SpoofGuard profile that has Port Binding enabled, this is a finding.'
  desc 'fix', 'To create a segment profile with SpoofGuard enabled, do the following:

From the NSX-T Manager web interface, go to Networking >> Segments >> Segment Profiles >> Add Segment Profile >> SpoofGuard.

Enter a profile name and enable port bindings, then click "Save".

To update a Segments SpoofGuard profile, do the following:

From the NSX-T Manager web interface, go to the Networking >> Segments, and click "Edit" from the drop-down menu next to the target Segment.

Expand "Segment Profiles" then choose the new SpoofGuard profile from the drop-down list, and then click "Save".'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Distributed Firewall'
  tag check_id: 'C-55169r810048_chk'
  tag severity: 'medium'
  tag gid: 'V-251732'
  tag rid: 'SV-251732r810050_rule'
  tag stig_id: 'TDFW-3X-000036'
  tag gtitle: 'SRG-NET-000392-FW-000042'
  tag fix_id: 'F-55123r810049_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
