control 'SV-207463' do
  title 'The VMM must, for networked systems, compare internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal VMM clocks provides uniformity of time stamps for VMMs with multiple system clocks and systems connected over a network.

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', 'Verify the VMM, for networked systems, compares internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM, for networked systems, to compare internal information system clocks at least every 24 hours with a server which is synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DoD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7720r878141_chk'
  tag severity: 'medium'
  tag gid: 'V-207463'
  tag rid: 'SV-207463r878143_rule'
  tag stig_id: 'SRG-OS-000355-VMM-001330'
  tag gtitle: 'SRG-OS-000355'
  tag fix_id: 'F-7720r878142_fix'
  tag 'documentable'
  tag legacy: ['SV-71387', 'V-57127']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
