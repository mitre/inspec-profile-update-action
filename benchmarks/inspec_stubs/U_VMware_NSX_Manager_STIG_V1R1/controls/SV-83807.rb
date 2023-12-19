control 'SV-83807' do
  title 'The NSX Manager must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity. Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'Verify NSX Manager has the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.

Log on to NSX Manager with credentials authorized for administration, navigate and select Manage Appliance Settings >> Time Settings. 

Verify NTP Servers have the correct time sources.

If the NSX Manager does not have primary and secondary time sources located in different geographic regions using redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Change the primary and secondary time sources on the NSX Manager to time sources located in different geographic regions using redundant authoritative time sources.

Log on to NSX Manager with credentials authorized for administration. Navigate and select Manage Appliance Settings >> Time Settings >> Edit. Add NTP Servers to the correct time sources.

If the NSX Manager does not have primary and secondary time sources located in different geographic regions using redundant authoritative time sources, this is a finding.'
  impact 0.3
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69643r1_chk'
  tag severity: 'low'
  tag gid: 'V-69203'
  tag rid: 'SV-83807r1_rule'
  tag stig_id: 'VNSX-ND-000100'
  tag gtitle: 'SRG-APP-000371-NDM-000296'
  tag fix_id: 'F-75389r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
