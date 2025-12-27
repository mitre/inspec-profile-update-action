control 'SV-254248' do
  title 'Windows Server 2022 must use an antivirus program.'
  desc 'Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Verify an antivirus solution is installed on the system. The antivirus solution may be bundled with an approved host-based security solution.

If there is no antivirus solution installed on the system, this is a finding.

Verify if Microsoft Defender antivirus is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName"

Verify if third-party antivirus is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName

Enter "get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName'
  desc 'fix', 'If no antivirus software is in use, install Microsoft Defender or third-party antivirus.

Open "PowerShell".

Enter "Install-WindowsFeature -Name Windows-Defender".

For third-party antivirus, install per antivirus instructions and disable Windows Defender.

Open "PowerShell".

Enter "Uninstall-WindowsFeature -Name Windows-Defender".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57733r848558_chk'
  tag severity: 'medium'
  tag gid: 'V-254248'
  tag rid: 'SV-254248r848560_rule'
  tag stig_id: 'WN22-00-000110'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-57684r848559_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
