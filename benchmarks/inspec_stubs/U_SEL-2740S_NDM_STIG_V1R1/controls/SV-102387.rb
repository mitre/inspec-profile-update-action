control 'SV-102387' do
  title 'The SEL-2740S must be configured to synchronize internal system clocks with an authoritative time source.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems). Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in CCI-001891 because a comparison must be done in order to determine the time difference.

The organization-defined time period will depend on multiple factors, most notably the granularity of time stamps in audit logs. For example, if time stamps only show to the nearest second, there is no need to have accuracy of a tenth of a second in clocks.'
  desc 'check', 'To ensure SEL-2740S NTP servers are configured do the following:
1. Log in with Permission Level 3 rights into parent OTSDN Controller.
2. Go to the "configuration object" page.
3. Check NTP Server IP addresses in the settings fields.
4. Check NTP flows for the SEL-2740S DUT and additional neighbor devices exist and are correct.

If the SEL-2740S is not configured to maintain internal system clocks with an authoritative time server, this is a finding.'
  desc 'fix', 'Configure NTP Servers during node adoption with the following steps:
1. Go to the "configuration object" page and select desired switch.
2. Enter the NTP Server IP addresses in appropriate settings fields for primary and backup NTP server(s).
3. Click "Submit".
4. Create NTP Flows to/from NTP server to/from node.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-91595r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92299'
  tag rid: 'SV-102387r1_rule'
  tag stig_id: 'SELS-ND-001010'
  tag gtitle: 'SRG-APP-000372-NDM-000297'
  tag fix_id: 'F-98537r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end
