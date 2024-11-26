control 'SV-228664' do
  title 'The Palo Alto Networks security platform must synchronize internal information system clocks to the authoritative time source when the time difference is greater than one second.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. 

The Palo Alto Networks security platform can be configured to use specified Network Time Protocol (NTP) servers.  Network Time Protocol (NTP) is used to synchronize the system clock of a computer to reference time source.  Sources outside of the configured acceptable allowance (drift) may be inaccurate.  When properly configured, NTP will synchronize all participating computers to within a few milliseconds of the reference time source.'
  desc 'check', 'Go to Device >> Setup >> Services
In the "Services" window, the names or IP addresses of the Primary NTP Server and Secondary NTP Server must be present.
If the "Primary NTP Server" and "Secondary NTP Server" fields are blank, this is a finding.'
  desc 'fix', 'Go to Device >> Setup >> Services
Select the "Edit" icon (the gear symbol in the upper-right corner of the pane).
In the "Services" window, in the "Primary NTP Server Address" field and the "Secondary NTP Server Address" field, enter the IP address or hostname of the NTP servers.

In the "Authentication Type" field, select one of the following:
None (default); this option disables NTP authentication.
Symmetric Key; this option uses symmetric key exchange, which are shared secrets. Enter the key ID, algorithm, authentication key, and confirm the authentication key.
Autokey; this option uses auto key, or public key cryptography.
Commit changes by selecting "Commit" in the upper-right corner of the screen.
Select "OK" when the confirmation dialog appears.'
  impact 0.3
  ref 'DPMS Target Palo Alto Networks NDM'
  tag check_id: 'C-30899r513595_chk'
  tag severity: 'low'
  tag gid: 'V-228664'
  tag rid: 'SV-228664r856010_rule'
  tag stig_id: 'PANW-NM-000099'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-30876r513596_fix'
  tag 'documentable'
  tag legacy: ['SV-77245', 'V-62755']
  tag cci: ['CCI-000366', 'CCI-002046']
  tag nist: ['CM-6 b', 'AU-8 (1) (b)']
end
