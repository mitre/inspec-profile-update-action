control 'SV-251743' do
  title 'The NSX-T Tier-0 Gateway Firewall must configure SpoofGuard to block outbound IP packets that contain illegitimate packet attributes.'
  desc 'If outbound communications traffic is not filtered, hostile activity intended to harm other networks may not be detected and prevented.'
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Segments and for each Segment, view Segment Profiles >> SpoofGuard.

If a Segment is not configured with a SpoofGuard profile that has Port Binding enabled, this is a finding.'
  desc 'fix', 'To create a segment profile with SpoofGuard enabled, do the following:

From the NSX-T Manager web interface, go to Networking >> Segments >> Segment Profiles >> Add Segment Profile >> SpoofGuard.

Enter a profile name, enable port bindings, and then click "Save".

To update a Segments SpoofGuard profile, do the following:

From the NSX-T Manager web interface, go to Networking >> Segments and click "Edit" from the drop-down menu next to the target Segment.

Expand Segment Profiles, choose the new SpoofGuard profile from the drop-down list, and then click "Save".'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway Firewall'
  tag check_id: 'C-55180r810094_chk'
  tag severity: 'medium'
  tag gid: 'V-251743'
  tag rid: 'SV-251743r810096_rule'
  tag stig_id: 'T0FW-3X-000036'
  tag gtitle: 'SRG-NET-000364-FW-000042'
  tag fix_id: 'F-55134r810095_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
