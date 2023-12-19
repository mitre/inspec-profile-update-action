control 'SV-80739' do
  title 'The HP FlexFabric Switch must synchronize internal information system clocks to the authoritative time source when the time difference is greater than the organization-defined time period.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems). Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in CCI-001891 because a comparison must be done in order to determine the time difference.

The organization-defined time period will depend on multiple factors, most notably the granularity of time stamps in audit logs. For example, if time stamps only show to the nearest second, there is no need to have accuracy of a tenth of a second in clocks.'
  desc 'check', 'Check the HP FlexFabric Switch configuration to determine if it synchronizes internal information system clocks to the authoritative time source when the time difference is greater than the organization-defined time period.

[HP] display ntp status

 Clock status: synchronized
 Clock stratum: 4
 System peer: 16.110.135.123
 Local mode: client
 Reference clock ID: 16.110.135.123
 Leap indicator: 00
 Clock jitter: 0.004227 s
 Stability: 0.000 pps
 Clock precision: 2^-19
 Root delay: 96.75598 ms
 Root dispersion: 149.76501 ms
 Reference time: d916fabd.a5c6d326  Mon, Jun  1 2015  9:37:33.647

If this synchronization is not occurring when the time difference is greater than the organization-defined time period, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to synchronize internal information system clocks to the authoritative time source when the time difference is greater than the organization-defined time period.

[HP] ntp enable
[HP] ntp unicast-server 16.110.135.123'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66895r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66249'
  tag rid: 'SV-80739r1_rule'
  tag stig_id: 'HFFS-ND-000099'
  tag gtitle: 'SRG-APP-000372-NDM-000297'
  tag fix_id: 'F-72325r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end
