control 'SV-203711' do
  title 'The operating system must, for networked systems, compare internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'Verify the operating system, for networked systems, compares internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS). If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to, for networked systems, compare internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers, or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3836r877021_chk'
  tag severity: 'medium'
  tag gid: 'V-203711'
  tag rid: 'SV-203711r877963_rule'
  tag stig_id: 'SRG-OS-000355-GPOS-00143'
  tag gtitle: 'SRG-OS-000355'
  tag fix_id: 'F-3836r877963_fix'
  tag 'documentable'
  tag legacy: ['V-57267', 'SV-71527']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
