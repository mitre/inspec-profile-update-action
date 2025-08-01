control 'SV-103401' do
  title 'Windows Server 2019 Exploit Protection system-level mitigation, Data Execution Prevention (DEP), must be on.'
  desc 'Exploit protection enables mitigations against potential threats at the system and application level.  Several mitigations, including "Data Execution Prevention (DEP)", are enabled by default at the system level. DEP prevents code from being run from data-only memory pages. If this is turned off, Windows may be subject to various exploits.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

The default configuration in Exploit Protection is "On by default" which meets this requirement.  The PowerShell query results for this show as "NOTSET".

Run "Windows PowerShell" with elevated privileges (run as administrator).

Enter "Get-ProcessMitigation -System".

If the status of "DEP: Enable" is "OFF", this is a finding.

Values that would not be a finding include:

ON
NOTSET (Default configuration)'
  desc 'fix', 'Ensure Exploit Protection system-level mitigation, "Data Execution Prevention (DEP)", is turned on.  The default configuration in Exploit Protection is "On by default" which meets this requirement.

Open "Windows Defender Security Center".

Select "App & browser control".

Select "Exploit protection settings".

Under "System settings", configure "Data Execution Prevention (DEP)" to "On by default" or "Use default (<On>)".   

The STIG package includes a DoD EP XML file in the "Supporting Files" folder for configuring application mitigations defined in the STIG.  This can also be modified to explicitly enforce the system level requirements.  Adding the following to the XML file will explicitly turn DEP on (other system level EP requirements can be combined under <SystemConfig>):

<SystemConfig>
  <DEP Enable="true"></DEP>
</SystemConfig>

The XML file is applied with the group policy setting Computer Configuration >> Administrative Settings >> Windows Components >> Windows Defender Exploit Guard >> Exploit Protection >> "Use a common set of exploit protection settings" configured to "Enabled" with file name and location defined under "Options:". It is recommended the file be in a read-only network location.'
  impact 0.5
  ref 'DPMS Target Windows 2019'
  tag check_id: 'C-92631r1_chk'
  tag severity: 'medium'
  tag gid: 'V-93313'
  tag rid: 'SV-103401r1_rule'
  tag stig_id: 'WN19-EP-000010'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-99559r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
