control 'SV-242629' do
  title 'The Cisco ISE must be configured to synchronize internal information system clocks using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. The network device must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. This requirement is related to the comparison done in CCI-001891.

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source.'
  desc 'check', '1. View the status of the Network Translation Protocol (NTP) associations.
show ntp
2. Verify a primary and secondary ntp server address is configured.

If the Cisco ISE is not configured to synchronize internal information system clocks using redundant authoritative time sources, this is a finding.'
  desc 'fix', '1. Choose Administration >> System >> Settings >> System Time.
2.  Enter unique IP addresses (IPv4/IPv6/FQDN) for the NTP servers.
3.  Check the "Only allow authenticated NTP servers" check box if you want to restrict Cisco ISE to use only authenticated NTP servers to keep system and network time.
DoD requires NTP authentication where available, so configure the NTP server using private keys. Click the NTP Authentication Keys tab and specify one or more authentication keys if any of the servers that you specify requires authentication via an authentication key, as follows:
4. Click "Add".
5. Enter the necessary Key ID and Key Value. Specify whether the key in question is trusted by activating or deactivating the Trusted Key option, and click "OK". The Key ID field supports numeric values between 1 and 65535 and the Key Value field supports up to 15 alphanumeric characters.
6. Return to the NTP Server Configuration tab after entering the NTP Server Authentication Keys.
7. Click "Save".'
  impact 0.5
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45904r714195_chk'
  tag severity: 'medium'
  tag gid: 'V-242629'
  tag rid: 'SV-242629r851060_rule'
  tag stig_id: 'CSCO-NM-000230'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-45861r714196_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end
