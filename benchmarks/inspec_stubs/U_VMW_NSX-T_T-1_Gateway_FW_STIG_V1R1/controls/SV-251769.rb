control 'SV-251769' do
  title 'The NSX-T Tier-1 Gateway Firewall must configure SpoofGuard to block outbound IP packets that contain illegitimate packet attributes.'
  desc 'If outbound communications traffic is not filtered, hostile activity intended to harm other networks may not be detected and prevented.'
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Segments, and for each Segment, view Segment Profiles >> SpoofGuard.

If a Segment is not configured with a SpoofGuard profile that has Port Binding enabled, this is a finding.'
  desc 'fix', %q(To create a segment profile with SpoofGuard enabled do the following:

From the NSX-T Manager web interface, go to Networking >> Segments >> Segment Profiles >> Add Segment Profile >> SpoofGuard.

Enter a profile name and enable port bindings, then click "Save".

To update a Segment's SpoofGuard profile, do the following:

From the NSX-T Manager web interface, go to the Networking >> Segments, then click "Edit" from the drop-down menu next to the target Segment.

Expand Segment Profiles, choose the new SpoofGuard profile from the drop-down list, and then click "Save".)
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier 1 Gateway Firewall'
  tag check_id: 'C-55206r810200_chk'
  tag severity: 'medium'
  tag gid: 'V-251769'
  tag rid: 'SV-251769r810202_rule'
  tag stig_id: 'T1FW-3X-000036'
  tag gtitle: 'SRG-NET-000392-FW-000042'
  tag fix_id: 'F-55160r810201_fix'
  tag 'documentable'
  tag cci: ['CCI-002664']
  tag nist: ['SI-4 (5)']
end
