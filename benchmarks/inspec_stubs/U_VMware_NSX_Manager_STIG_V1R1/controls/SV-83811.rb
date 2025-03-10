control 'SV-83811' do
  title 'The NSX Manager must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 
 
Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.
 
DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'Verify NSX Manager has the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.

Log on to NSX Manager with credentials authorized for administration, navigate and select Manage Appliance Settings >> Time Settings.

Verify NTP Servers have the correct time sources.

If the NSX Manager does not have primary and secondary time sources located in different geographic regions using redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Change the primary and secondary time sources on the NSX Manager to time sources located in different geographic regions using redundant authoritative time sources.

Log on to NSX Manager with credentials authorized for administration, navigate and select Manage Appliance Settings >> Time Settings >> Edit. Add NTP Servers to the correct time sources.

If the NSX Manager does not have primary and secondary time sources located in different geographic regions using redundant authoritative time sources, this is a finding.'
  impact 0.5
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69647r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69207'
  tag rid: 'SV-83811r1_rule'
  tag stig_id: 'VNSX-ND-000102'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-75393r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end
