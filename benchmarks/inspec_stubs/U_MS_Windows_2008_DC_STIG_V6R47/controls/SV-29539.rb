control 'SV-29539' do
  title 'The time service must synchronize with an appropriate DoD time source.'
  desc 'The Windows Time Service controls time synchronization settings. Time synchronization is essential for authentication and auditing purposes. If the Windows Time Service is used, it must synchronize with a secure, authorized time source. Domain joined systems are automatically configured to synchronize with domain controllers. If an NTP server is configured, it must synchronize with a secure, authorized time source.'
  desc 'check', 'Open an elevated "Command Prompt" (run as administrator).

Enter "W32tm /query /configuration".

Domain-joined systems are automatically configured with a "Type" of "NT5DS" to synchronize with domain controllers and would not be a finding.

If systems are configured with a "Type" of "NTP", including standalone systems and the forest root domain controller with the PDC Emulator role, and do not have a DoD time server defined for "NTPServer", this is a finding. (See V-8557 in the Active Directory Forest STIG for the time source requirement of the forest root domain PDC emulator.)

If an alternate time synchronization tool is used and is not enabled or not configured to synchronize with a DoD time source, this is a finding.

The US Naval Observatory operates stratum 1 time servers, identified at http://tycho.usno.navy.mil/ntp.html. Time synchronization will occur through a hierarchy of time servers down to the local level. Clients and lower-level servers will synchronize with an authorized time server in the hierarchy.'
  desc 'fix', 'If the system needs to be configured to an NTP server, configure the system to point to an authorized time server by setting the policy value for Computer Configuration >> Administrative Templates >> System >> Windows Time Service >> Time Providers >> "Configure Windows NTP Client" to "Enabled", and configure the "NtpServer" field to point to an authorized time server.   

The US Naval Observatory operates stratum 1 time servers, identified at http://tycho.usno.navy.mil/ntp.html. Time synchronization will occur through a hierarchy of time servers down to the local level. Clients and lower-level servers will synchronize with an authorized time server in the hierarchy.'
  impact 0.3
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-80211r2_chk'
  tag severity: 'low'
  tag gid: 'V-3472'
  tag rid: 'SV-29539r2_rule'
  tag gtitle: 'Windows Time Service - Configure NTP Client'
  tag fix_id: 'F-87331r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
