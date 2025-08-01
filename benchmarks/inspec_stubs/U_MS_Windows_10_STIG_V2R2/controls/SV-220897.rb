control 'SV-220897' do
  title 'Exploit Protection mitigations in Windows 10 must be configured for VISIO.EXE.'
  desc 'Exploit protection in Windows 10 provides a means of enabling additional mitigations against potential threats at the system and application level. Without these additional application protections, Windows 10 may be subject to various exploits.'
  desc 'check', 'This is NA prior to v1709 of Windows 10.

This is applicable to unclassified systems, for other systems this is NA.

Run "Windows PowerShell" with elevated privileges (run as administrator).

Enter "Get-ProcessMitigation -Name VISIO.EXE".
(Get-ProcessMitigation can be run without the -Name parameter to get a list of all application mitigations configured.)

If the following mitigations do not have the listed status which is shown below, this is a finding:

DEP:
Override DEP: False

ASLR:
ForceRelocateImages: ON

Payload:
OverrideExportAddressFilter: False
OverrideExportAddressFilterPlus: False
OverrideImportAddressFilter: False
OverrideEnableRopStackPivot: False
OverrideEnableRopCallerCheck: False
OverrideEnableRopSimExec: False

The PowerShell command produces a list of mitigations; only those with a required status are listed here. If the PowerShell command does not produce results, ensure the letter case of the filename within the command syntax matches the letter case of the actual filename on the system.'
  desc 'fix', 'Ensure the following mitigations are configured as shown for VISIO.EXE:

DEP:
Override DEP: False

ASLR:
ForceRelocateImages: ON

Payload:
OverrideExportAddressFilter: False
OverrideExportAddressFilterPlus: False
OverrideImportAddressFilter: False
OverrideEnableRopStackPivot: False
OverrideEnableRopCallerCheck: False
OverrideEnableRopSimExec: False

Application mitigations defined in the STIG are configured by a DoD EP XML file included with the Windows 10 STIG package in the "Supporting Files" folder.

The XML file is applied with the group policy setting Computer Configuration >> Administrative Settings >> Windows Components >> Windows Defender Exploit Guard >> Exploit Protection >> "Use a common set of exploit protection settings" configured to "Enabled" with file name and location defined under "Options:".  It is recommended the file be in a read-only network location.'
  impact 0.5
  ref 'DPMS Target Windows 10'
  tag check_id: 'C-22612r555176_chk'
  tag severity: 'medium'
  tag gid: 'V-220897'
  tag rid: 'SV-220897r569187_rule'
  tag stig_id: 'WN10-EP-000260'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-22601r555177_fix'
  tag 'documentable'
  tag legacy: ['SV-91951', 'V-77255']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
