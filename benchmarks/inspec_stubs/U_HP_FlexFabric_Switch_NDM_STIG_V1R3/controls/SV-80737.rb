control 'SV-80737' do
  title 'The HP FlexFabric Switch must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity. Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'Check the HP FlexFabric Switch configuration to determine if compares internal information system clocks at least every 24 hours with an authoritative time server.

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

If this comparison does not occur at least every 24 hours, this is a finding.'
  desc 'fix', 'Configure the HP FlexFabric Switch to compare internal information system clocks at least every 24 hours with an authoritative time server.

[HP] ntp enable
[HP] ntp unicast-server 16.110.135.123'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 NDM'
  tag check_id: 'C-66893r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66247'
  tag rid: 'SV-80737r1_rule'
  tag stig_id: 'HFFS-ND-000098'
  tag gtitle: 'SRG-APP-000371-NDM-000296'
  tag fix_id: 'F-72323r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
