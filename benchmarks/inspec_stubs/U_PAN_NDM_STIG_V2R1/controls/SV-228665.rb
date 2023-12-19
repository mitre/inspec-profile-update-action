control 'SV-228665' do
  title 'The Palo Alto Networks security platform must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc 'The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes its time to a more accurate source. 

DoD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: a time server designated for the appropriate DoD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region from the primary time source.'
  desc 'check', 'Go to Device >> Setup >> Services
If there is only one NTP Server configured, this is a finding.

Ask the firewall administrator where the Primary NTP Server and Secondary NTP Server are located; if they are not in different geographic regions, this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Services
Select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Services" window, in the "Primary NTP Server Address" field and the "Secondary NTP Server Address" field, enter the IP address or hostname of the NTP servers.

In the "Authentication Type" field, select one of the following:
None (default); this option disables NTP authentication.
Symmetric Key; this option uses symmetric key exchange, which are shared secrets. Enter the key ID, algorithm, authentication key, and confirm the authentication key.
Autokey; this option uses auto key, or public key cryptography.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.5
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30900r513598_chk'
  tag severity: 'medium'
  tag gid: 'V-228665'
  tag rid: 'SV-228665r513600_rule'
  tag stig_id: 'PANW-NM-000100'
  tag gtitle: 'SRG-APP-000373-NDM-000298'
  tag fix_id: 'F-30877r513599_fix'
  tag 'documentable'
  tag legacy: ['SV-77247', 'V-62757']
  tag cci: ['CCI-000366', 'CCI-001893']
  tag nist: ['CM-6 b', 'AU-8 (2)']
end
