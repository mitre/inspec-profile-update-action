control 'SV-220707' do
  title 'The Windows 10 system must use an anti-virus program.'
  desc 'Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  desc 'check', 'Verify an anti-virus solution is installed on the system and in use. The anti-virus solution may be bundled with an approved Endpoint Security Solution.

Verify if Windows Defender is in use or enabled:

Open "PowerShell".

Enter “get-service | where {$_.DisplayName -Like "*Defender*"} | Select Status,DisplayName”

Verify third-party antivirus is in use or enabled:

Open "PowerShell".

Enter “get-service | where {$_.DisplayName -Like "*mcafee*"} | Select Status,DisplayName”

Enter “get-service | where {$_.DisplayName -Like "*symantec*"} | Select Status,DisplayName”

If there is no anti-virus solution installed on the system, this is a finding.'
  desc 'fix', 'If no anti-virus software is on the system and in use, install Windows Defender or a third-party anti-virus solution.'
  impact 0.7
  ref 'DPMS Target Windows 10'
  tag check_id: 'C-22422r793192_chk'
  tag severity: 'high'
  tag gid: 'V-220707'
  tag rid: 'SV-220707r793194_rule'
  tag stig_id: 'WN10-00-000045'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22411r793193_fix'
  tag 'documentable'
  tag legacy: ['SV-77841', 'V-63351']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
