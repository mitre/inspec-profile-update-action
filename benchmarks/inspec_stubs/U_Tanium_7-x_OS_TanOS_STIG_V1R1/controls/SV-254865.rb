control 'SV-254865' do
  title 'The Tanium operating system (TanOS) must, for networked systems, compare internal information system clocks at least every 24 hours with a server synchronized to one of the redundant United States Naval Observatory (USNO) time servers or a time server designated for the appropriate DOD network (NIPRNet/SIPRNet), and/or the Global Positioning System (GPS).'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside of the configured acceptable allowance (drift) may be inaccurate. 

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. 

Organizations should consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints).'
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "A" for "Appliance Configuration Menu," and then press "Enter".

4. Press "3" for "NTP Configuration," and then press "Enter".

If there is no address listed for "Currently configured ntp servers:", this is a finding.

If the "Current NTP Status" does not list a status of "Synchronized to NTP Server (<address>) at stratum #" and "Time correct to within # ms", this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "A" for "Appliance Configuration Menu," and then press "Enter".

4. Press "3" for "NTP Configuration," and then press "Enter".

5. Type "Yes" to "Remove the current NTP servers and enter new information?" and then press "Enter".

6. Type the first NTP server address, and then press "Enter".

7. Type "Yes" to provide a second NTP Server, and then press "Enter".

8. Type the second NTP server address and then press "Enter".

9. Press "Enter" to return to the "Appliance Configuration" menu.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58478r866134_chk'
  tag severity: 'medium'
  tag gid: 'V-254865'
  tag rid: 'SV-254865r870374_rule'
  tag stig_id: 'TANS-OS-001095'
  tag gtitle: 'SRG-OS-000355'
  tag fix_id: 'F-58422r870373_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
