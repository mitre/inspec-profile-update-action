control 'SV-253296' do
  title 'The Windows 11 time service must synchronize with an appropriate DOD time source.'
  desc 'The Windows Time Service controls time synchronization settings. Time synchronization is essential for authentication and auditing purposes. If the Windows Time Service is used, it must synchronize with a secure, authorized time source. Domain-joined systems are automatically configured to synchronize with domain controllers. If an NTP server is configured, it must synchronize with a secure, authorized time source.'
  desc 'check', 'Review the Windows time service configuration.

Open an elevated "Command Prompt" (run as administrator).

Enter "W32tm /query /configuration".

Domain-joined systems (excluding the domain controller with the PDC emulator role):

If the value for "Type" under "NTP Client" is not "NT5DS", this is a finding.'
  desc 'fix', 'Configure the system to synchronize time with an appropriate DOD time source.

Domain-joined systems use NT5DS to synchronize time from other systems in the domain by default.

If the system needs to be configured to an NTP server, configure the system to point to an authorized time server by setting the policy value for Computer Configuration >> Administrative Templates >> System >> Windows Time Service >> Time Providers >> "Configure Windows NTP Client" to "Enabled", and configure the "NtpServer" field to point to an appropriate DOD time server.

The US Naval Observatory operates stratum 1 time servers, identified at https://www.cnmoc.usff.navy.mil/Our-Commands/United-States-Naval-Observatory/Precise-Time-Department/Network-Time-Protocol-NTP/. Time synchronization will occur through a hierarchy of time servers down to the local level. Clients and lower-level servers will synchronize with an authorized time server in the hierarchy.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56749r828970_chk'
  tag severity: 'low'
  tag gid: 'V-253296'
  tag rid: 'SV-253296r922043_rule'
  tag stig_id: 'WN11-00-000260'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-56699r922035_fix'
  tag 'documentable'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
