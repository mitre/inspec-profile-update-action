control 'SV-254866' do
  title 'The Tanium Operating System (TanOS) must synchronize internal information system clocks to the authoritative time source when the time difference is greater than the organization-defined time period.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. 

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network. Organizations should consider setting time periods for different types of systems (e.g., financial, legal, or mission-critical systems). 

Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done every 24 hours in CCI-001891 because a comparison must be done in order to determine the time difference.'
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

6. Type the first NTP server address and then press "Enter".

7. Type "Yes" to provide a second NTP Server, and then press "Enter".

8. Type the second NTP server address and then press "Enter".

8. Press "Enter" to return to the "Appliance Configuration" menu.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58479r866137_chk'
  tag severity: 'medium'
  tag gid: 'V-254866'
  tag rid: 'SV-254866r866139_rule'
  tag stig_id: 'TANS-OS-001100'
  tag gtitle: 'SRG-OS-000356'
  tag fix_id: 'F-58423r866138_fix'
  tag 'documentable'
  tag cci: ['CCI-002046']
  tag nist: ['AU-8 (1) (b)']
end
