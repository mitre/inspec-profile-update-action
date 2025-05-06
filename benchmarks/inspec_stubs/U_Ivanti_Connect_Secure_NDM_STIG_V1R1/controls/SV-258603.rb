control 'SV-258603' do
  title 'The ICS must be configured to authenticate Network Time Protocol (NTP) sources using authentication that is cryptographically based.'
  desc 'If Network Time Protocol is not authenticated, an attacker can introduce a rogue NTP server. This rogue server can then be used to send incorrect time information to network devices, which will make log timestamps inaccurate and affect scheduled actions. NTP authentication is used to prevent this tampering by authenticating the time source.'
  desc 'check', 'In the ICS Web UI, navigate to System >> Status >> Dashboard.
1. Click the "Overview" tab.
2. Under "Appliance Details" and "System Date and Time", select "Edit".
3. Verify the "Use Pool of NTP servers" is checked with NTP server IPs defined.
4. Verify the NTP server IP/hostname is defined with a key.

If the ICS does not authenticate NTP sources using authentication that is cryptographically based, this is a finding.'
  desc 'fix', 'In the ICS Web UI, navigate to System >> Status >> Dashboard.
1. Click the "Overview" tab.
2. Under "Appliance Details" and "System Date and Time" select "Edit".
3. Select the Time Zone to use - DOD may require GMT.
4. Select "Use Pool of NTP servers".
5. Enter the IP/hostname of each NTP server in the "NTP Server 1", "NTP Server 2", etc.
6. Under the key section input the key in the following format: <keynumber> <algorithm> <key>
For example, it would be entered like this: 1 SHA1 NtPKey123.
Note: there must be a space between each section of <keynumber> <algorithm> <key>
7. Click "Save Changes".
8. Navigate to System >> Log/Monitoring >> Events.
9. Ensure an event log stating the time sync is successful.'
  impact 0.5
  ref 'DPMS Target Ivanti Connect Secure NDM'
  tag check_id: 'C-62343r930495_chk'
  tag severity: 'medium'
  tag gid: 'V-258603'
  tag rid: 'SV-258603r930497_rule'
  tag stig_id: 'IVCS-NM-000100'
  tag gtitle: 'SRG-APP-000395-NDM-000347'
  tag fix_id: 'F-62252r930496_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
