control 'SV-253264' do
  title 'The Windows 11 system must use an antivirus program.'
  desc 'Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Verify an antivirus solution is installed on the system and in use. The antivirus solution may be bundled with an approved Endpoint Security Solution.

Verify if Microsoft Defender Antivirus is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName"

Verify third-party antivirus is in use or enabled:

Open "PowerShell".

Enter "get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName"

Enter "get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName"

If there is no antivirus solution installed on the system, this is a finding.'
  desc 'fix', 'Install Microsoft Defender Antivirus or a third-party antivirus solution.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56717r828874_chk'
  tag severity: 'high'
  tag gid: 'V-253264'
  tag rid: 'SV-253264r828876_rule'
  tag stig_id: 'WN11-00-000045'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-56667r828875_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
