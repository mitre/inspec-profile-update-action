control 'SV-254867' do
  title 'The Tanium Operating System (TanOS) must be configured to synchronize internal information system clocks with the primary and secondary time sources located in different geographic regions using redundant authoritative time sources.'
  desc "The loss of connectivity to a particular authoritative time source will result in the loss of time synchronization (free-run mode) and increasingly inaccurate time stamps on audit events and other functions. 

Multiple time sources provide redundancy by including a secondary source. Time synchronization is usually a hierarchy; clients synchronize time to a local source while that source synchronizes it's time to a more accurate source. The system must utilize an authoritative time server and/or be configured to use redundant authoritative time sources. Organizations should also consider endpoints that may not have regular access to the authoritative time server (e.g., mobile, teleworking, and tactical endpoints). This requirement is related to the comparison done in CCI-001891.

DOD-approved solutions consist of a combination of a primary and secondary time source using a combination or multiple instances of the following: A time server designated for the appropriate DOD network (NIPRNet/SIPRNet); United States Naval Observatory (USNO) time servers; and/or the Global Positioning System (GPS). The secondary time source must be located in a different geographic region than the primary time source."
  desc 'check', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "A" for "Appliance Configuration Menu," and then press "Enter".

4. Press "3" for "NTP Configuration," and then press "Enter".

If there is no address or only a single address listed for "Currently configured ntp servers:", this is a finding.

If the "Currently configured ntp servers:" list is not the organizationally mandated list of geographically distributed time servers, this is a finding.'
  desc 'fix', '1. Access the Tanium Server interactively.

2. Log on to the TanOS server with the tanadmin role.

3. Press "A" for "Appliance Configuration Menu," and then press "Enter".

4. Press "3" for "NTP Configuration," and then press "Enter".

5. Type "Yes" to "Remove the current NTP servers and enter new information?" and press "Enter".

6. Type the first NTP server address and press "Enter".

7. Type "Yes" to provide a second NTP Server, and then press "Enter".

8. Type the second NTP server address, and then press "Enter".

9. Press "Enter" to return to the "Appliance Configuration" menu.'
  impact 0.5
  ref 'DPMS Target Tanium 7.x OS on TanOS'
  tag check_id: 'C-58480r866140_chk'
  tag severity: 'medium'
  tag gid: 'V-254867'
  tag rid: 'SV-254867r870376_rule'
  tag stig_id: 'TANS-OS-001105'
  tag gtitle: 'SRG-OS-000357'
  tag fix_id: 'F-58424r870375_fix'
  tag 'documentable'
  tag cci: ['CCI-001893']
  tag nist: ['AU-8 (2)']
end
