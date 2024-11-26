control 'SV-79639' do
  title 'The DataPower Gateway must compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity. Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'Using the DataPower web interface, go to Network >> Interface >> NTP Service. Confirm that the Administrative state is enabled, NTP Servers are configured, and that the Refresh Interval is set to 2040 seconds or less. If it is not, this is a finding.'
  desc 'fix', 'Configure the DataPower Gateway to synchronize internal information system clocks to the authoritative time source (NTP servers).

In the DataPower WebGUI, go to Network >> Interface >> NTP Service. Specify the IP addresses of several approved NTP servers. The refresh interval may be defined at any value between 60 and 86400 seconds.'
  impact 0.3
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65777r1_chk'
  tag severity: 'low'
  tag gid: 'V-65149'
  tag rid: 'SV-79639r1_rule'
  tag stig_id: 'WSDP-NM-000098'
  tag gtitle: 'SRG-APP-000371-NDM-000296'
  tag fix_id: 'F-71089r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
