control 'SV-90947' do
  title 'CounterACT must compare internal information systems clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events.

Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity. Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'Check the network device configuration to determine if the device compares internal information system clocks at least every 24 hours with an authoritative time server.

1. Open an SSH session and authenticate to the CounterACT command line.
2. Verify the configured NTP servers with the command "fstool ntp".
3. Run the "date" command to look at the current system time compared to the known good, Network Time Protocol (NTP) server time.

If the device does not compare internal information system clocks at least every 24 hours, this is a finding.'
  desc 'fix', 'Configure CounterACT to compare internal information system clocks at least every 24 hours with an authoritative time server.

1. Open an SSH session and authenticate to CounterACT command line.
2. Configure the NTP servers with the command "fstool ntp setup <ip address>".'
  impact 0.5
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75945r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76259'
  tag rid: 'SV-90947r1_rule'
  tag stig_id: 'CACT-NM-000036'
  tag gtitle: 'SRG-APP-000371-NDM-000296'
  tag fix_id: 'F-82895r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
