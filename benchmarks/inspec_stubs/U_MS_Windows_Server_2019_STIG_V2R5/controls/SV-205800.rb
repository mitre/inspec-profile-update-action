control 'SV-205800' do
  title 'The Windows Server 2019 time service must synchronize with an appropriate DoD time source.'
  desc 'The Windows Time Service controls time synchronization settings. Time synchronization is essential for authentication and auditing purposes. If the Windows Time Service is used, it must synchronize with a secure, authorized time source. Domain-joined systems are automatically configured to synchronize with domain controllers. If an NTP server is configured, it must synchronize with a secure, authorized time source.'
  desc 'check', 'Review the Windows time service configuration.

Open an elevated "Command Prompt" (run as administrator).

Enter "W32tm /query /configuration".

Domain-joined systems (excluding the domain controller with the PDC emulator role):

If the value for "Type" under "NTP Client" is not "NT5DS", this is a finding.

Other systems:

If systems are configured with a "Type" of "NTP", including standalone or nondomain-joined systems and the domain controller with the PDC Emulator role, and do not have a DoD time server defined for "NTPServer", this is a finding.

To determine the domain controller with the PDC Emulator role:

Open "PowerShell".

Enter "Get-ADDomain | FT PDCEmulator".'
  desc 'fix', 'Configure the system to synchronize time with an appropriate DoD time source.

Domain-joined systems use NT5DS to synchronize time from other systems in the domain by default.

If the system needs to be configured to an NTP server, configure the system to point to an authorized time server by setting the policy value for Computer Configuration >> Administrative Templates >> System >> Windows Time Service >> Time Providers >> "Configure Windows NTP Client" to "Enabled", and configure the "NtpServer" field to point to an appropriate DoD time server.

The US Naval Observatory operates stratum 1 time servers, which are identified at:
https://www.cnmoc.usff.navy.mil/Organization/United-States-Naval-Observatory/Precise-Time-Department/Network-Time-Protocol-NTP/

Time synchronization will occur through a hierarchy of time servers down to the local level. Clients and lower-level servers will synchronize with an authorized time server in the hierarchy.'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-6065r857304_chk'
  tag severity: 'low'
  tag gid: 'V-205800'
  tag rid: 'SV-205800r859311_rule'
  tag stig_id: 'WN19-00-000440'
  tag gtitle: 'SRG-OS-000355-GPOS-00143'
  tag fix_id: 'F-6065r857305_fix'
  tag 'documentable'
  tag legacy: ['V-93187', 'SV-103275']
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
