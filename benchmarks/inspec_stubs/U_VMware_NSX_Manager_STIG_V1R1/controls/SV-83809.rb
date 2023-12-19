control 'SV-83809' do
  title 'The NSX Manager must synchronize internal information system clocks to the authoritative time source when the time difference is greater than the organization-defined time period.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 
 
Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations must consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems). Organizations must also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in CCI-001891 because a comparison must be done in order to determine the time difference.
 
The organization-defined time period will depend on multiple factors, most notably the granularity of time stamps in audit logs. For example, if time stamps only show to the nearest second, there is no need to have accuracy of a tenth of a second in clocks.'
  desc 'check', 'Verify NSX Manager has the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.

Log on to NSX Manager with credentials authorized for administration, navigate and select Manage Appliance Settings >> Time Settings. 

Verify NTP Servers have the correct time sources.

If the NSX Manager does not have primary and secondary time sources located in different geographic regions using redundant authoritative time sources, this is a finding.'
  desc 'fix', 'Change the primary and secondary time sources on the NSX Manager to time sources located in different geographic regions using redundant authoritative time sources.

Log on to NSX Manager with credentials authorized for administration, navigate and select Manage Appliance Settings >> Time Settings >> Edit. Add NTP Servers to the correct time sources.

If the NSX Manager does not have primary and secondary time sources located in different geographic regions using redundant authoritative time sources, this is a finding.'
  impact 0.3
  ref 'DPMS Target VMware NSX 6 NDM'
  tag check_id: 'C-69645r1_chk'
  tag severity: 'low'
  tag gid: 'V-69205'
  tag rid: 'SV-83809r1_rule'
  tag stig_id: 'VNSX-ND-000101'
  tag gtitle: 'SRG-APP-000372-NDM-000297'
  tag fix_id: 'F-75391r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end
