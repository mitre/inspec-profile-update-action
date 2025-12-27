control 'SV-102385' do
  title 'The SEL-2740S must be configured to compare internal information system clocks at least every 24 hours with an authoritative time server.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. Additionally, unnecessary synchronization may have an adverse impact on system performance and may indicate malicious activity.  Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.'
  desc 'check', 'To ensure SEL-2740S NTP servers are configured do the following:
1. Log in with Permission Level 3 rights into parent OTSDN Controller.
2. Go to the "configuration object" settings page.
3. Check NTP Server IP addresses in the settings fields.  The SEL-2740S support primary and backup NTP servers so enter the IP address of the backup if desired so there are both primary and backup displayed.
4. Check NTP flows for the SEL-2740S DUT and additional neighbor devices exist and are correct.

If the SEL-2740S is not configured to maintain internal system clocks with an authoritative time server, this is a finding.'
  desc 'fix', 'Configure NTP Servers during node adoption with the following steps:
1. Go to the "configuration object" page.
2. Enter the NTP Server IP addresses in appropriate settings fields.  The SEL-2740S support primary and backup NTP servers so enter the IP address of the backup if desired so there are both primary and backup displayed.
3. Click "Submit".
4. Create NTP Flows to/from NTP server to/from node.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-91593r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92297'
  tag rid: 'SV-102385r1_rule'
  tag stig_id: 'SELS-ND-001000'
  tag gtitle: 'SRG-APP-000371-NDM-000296'
  tag fix_id: 'F-98535r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
