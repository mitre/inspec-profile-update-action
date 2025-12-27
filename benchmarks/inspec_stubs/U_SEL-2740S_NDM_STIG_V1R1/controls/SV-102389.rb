control 'SV-102389' do
  title 'The SEL-2740S must be configured to maintain internal system clocks with a backup authoritative time server.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', 'To ensure SEL-2740S NTP servers are configured do the following:
1. Log in with Permission Level 3 rights into parent OTSDN Controller.
2. Go to the "configuration object" page and select the desired switch.
3. Check NTP Server IP addresses in the settings fields that both a primary and backup NTP server is configured.
4. Check NTP flows for the SEL-2740S DUT and additional neighbor devices exist and are correct.

If the SEL-2740S is not configured to maintain internal system clocks with a backup authoritative time server, this is a finding.'
  desc 'fix', 'Configure NTP Servers during node adoption with the following steps:
1. Go to the "configuration object" page and select desired switch.
2. Enter the NTP Server IP addresses in appropriate settings fields for primary and backup NTP server(s).
3. Click "Submit".
4. Create NTP Flows to/from NTP server to/from node.'
  impact 0.5
  ref 'DPMS Target SEL SDN Switch NDM'
  tag check_id: 'C-91597r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92301'
  tag rid: 'SV-102389r1_rule'
  tag stig_id: 'SELS-ND-001020'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-98539r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end
