control 'SV-224829' do
  title 'The Windows Server 2016 system must use an anti-virus program.'
  desc 'Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Verify an anti-virus solution is installed on the system. The anti-virus solution may be bundled with an approved host-based security solution.

If there is no anti-virus solution installed on the system, this is a finding.

Verify if Windows Defender is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName”

Verify if third-party anti-virus is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName”

Enter "get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName”'
  desc 'fix', 'If no anti-virus software is in use, install Windows Defender or third-party anti-virus.

Open "PowerShell".

Enter "Install-WindowsFeature -Name Windows-Defender”

For third-party anti-virus, install per anti-virus instructions and disable Windows Defender.

Open "PowerShell".

Enter “Uninstall-WindowsFeature -Name Windows-Defender”.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26520r603246_chk'
  tag severity: 'high'
  tag gid: 'V-224829'
  tag rid: 'SV-224829r569237_rule'
  tag stig_id: 'WN16-00-000120'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-26508r603245_fix'
  tag 'documentable'
  tag legacy: ['SV-87893', 'V-73241']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
