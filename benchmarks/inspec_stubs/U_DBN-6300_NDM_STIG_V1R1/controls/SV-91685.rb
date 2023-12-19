control 'SV-91685' do
  title 'The DBN-6300 must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity. Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'Verify the configuration of the NTP server.

Navigate to Settings >> Initial Configuration >> Time.

View the "Time" settings window.

If an NTP server address is not configured, this is a finding.'
  desc 'fix', 'Configure the NTP server on the device. The time difference is part of the NTP protocol and is not configurable.

Navigate to Settings >> Initial Configuration >> Time.

In the "Time" settings window, select the "NTP" button and enter the NTP server address.

Click on "Commit".'
  impact 0.5
  ref 'DPMS Target DB Networks DBN-6300 NDM'
  tag check_id: 'C-76615r1_chk'
  tag severity: 'medium'
  tag gid: 'V-76989'
  tag rid: 'SV-91685r1_rule'
  tag stig_id: 'DBNW-DM-000100'
  tag gtitle: 'SRG-APP-000371-NDM-000296'
  tag fix_id: 'F-83685r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
