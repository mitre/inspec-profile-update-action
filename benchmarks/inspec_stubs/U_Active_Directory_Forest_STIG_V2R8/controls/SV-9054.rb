control 'SV-9054' do
  title 'The Windows Time Service on the forest root PDC Emulator must be configured to acquire its time from an external time source.'
  desc 'When the Windows Time service is used to synchronize time on client computers (workstations and servers) throughout an AD forest, the forest root domain PDC Emulator is the normal default to provide the authoritative time source for the entire forest. To obtain an accurate time for itself, the forest root domain PDC Emulator acts as a client to an external time source.

If the Windows Time service on the forest root domain PDC Emulator is not configured to acquire the time from a proper source, it may cause time service clients throughout the forest to operate with the inaccurate time setting.

When a Windows computer operates with an inaccurate time setting, access to resources on computers with the accurate time might be denied. This is notably true when Kerberos authentication is utilized. Operation with an inaccurate time setting can reduce the value of audit data and invalidate it as a source of forensic evidence in an incident investigation.'
  desc 'check', 'This applies to the domain controller with the PDC emulator role in forest root domain; it is NA for other domain controllers in the forest.

Determine the domain controller with the PDC Emulator role in the forest root domain:

Windows 2008 R2 or later: 

Open "Windows PowerShell".

Enter "Get-ADDomain -Identity [Forest Root Domain] | FT PDCEmulator", where [Forest Root Domain] is the forest root domain name, such as "example.mil". (This can also be entered without the -Identity parameter if running within the forest root domain.)

Windows 2008:

Open "Active Directory Users and Computers" from a domain controller in or connected to the forest root (available from various menus or run "dsa.msc").

Select "Action" in the menu, then "All Tasks >> Operations Masters".

Select the "PDC" tab.

On the system with the PDC Emulator role, open "Windows PowerShell" or an elevated "Command Prompt" (run as administrator).

Enter "W32tm /query /configuration".

Under the "NtpClient" section:

If the value for "Type" is not "NTP", this is a finding.

If the value for "NtpServer" is not an external DoD time source, this is a finding.

If an alternate time synchronization tool is used and is not enabled or not configured to a synchronize with an external DoD time source, this is a finding.

The US Naval Observatory operates stratum 1 time servers, identified at http://tycho.usno.navy.mil/ntp.html. Time synchronization will occur through a hierarchy of time servers down to the local level. Clients and lower-level servers will synchronize with an authorized time server in the hierarchy.'
  desc 'fix', 'Configure the forest root PDC Emulator to acquire its time from an external time source.   

The Windows Time Service can be configured by setting the policy value for Computer Configuration >> Administrative Templates >> System >> Windows Time Service >> Time Providers >> "Configure Windows NTP Client" to "Enabled", and configure the "NtpServer" field to point to an authorized time server.'
  impact 0.5
  ref 'DPMS Target Active Directory Forest'
  tag check_id: 'C-80209r2_chk'
  tag severity: 'medium'
  tag gid: 'V-8557'
  tag rid: 'SV-9054r3_rule'
  tag stig_id: 'AD.0295'
  tag gtitle: 'Time Synchronization-Authoritative Source'
  tag fix_id: 'F-87329r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag cci: ['CCI-001891']
  tag nist: ['AU-8 (1) (a)']
end
