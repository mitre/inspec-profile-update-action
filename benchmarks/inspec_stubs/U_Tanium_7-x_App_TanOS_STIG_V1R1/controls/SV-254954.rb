control 'SV-254954' do
  title 'Tanium endpoint files must be excluded from host-based intrusion prevention intervention.'
  desc 'Similar to any other host-based applications, the Tanium Client is subject to the restrictions other system-level software may place on an operating environment. Antivirus, IPS, Encryption, or other security and management stack software may disallow the Tanium Server from working as expected.

https://docs.tanium.com/client/client/requirements.html#Host_system_security_exceptions'
  desc 'check', 'Consult with the Tanium System Administrator to determine the HIPS software used on the Tanium Clients.

Review the settings of the HIPS software.

Validate exclusions exist which exclude the Tanium program files from being restricted by HIPS.

If exclusions do not exist, this is a finding.'
  desc 'fix', 'In the host-based intrusion prevention system, ensure the following folders are excluded:

Windows (64-bit OS versions) - \\Program Files (x86)\\Tanium\\Tanium Client
Windows (32-bit OS versions) - \\Program Files\\Tanium\\Tanium Client
macOS - /Library/Tanium/TaniumClient
Linux, Solaris, AIX - /opt/Tanium/TaniumClient

In the host-based intrusion prevention system, ensure the following processes are excluded:

Windows, macOS, Linux - <Tanium Client>/Tools/StdUtils directory or all the files that it contains, including:

Windows, macOS, Linux - 7za.exe (Windows) or 7za (macOS, Linux)
Windows, macOS, Linux - runasuser.exe (Windows only)
Windows, macOS, Linux - runasuser64.exe (Windows only)
Windows, macOS, Linux - TaniumExecWrapper.exe (Windows) or TaniumExecWrapper (macOS, Linux)
Windows, macOS, Linux - TaniumFileInfo.exe (Windows only)
Windows, macOS, Linux - TPowerShell.exe (Windows only)
macOS, Linux, Solaris, AIX - <Tanium Client>/TaniumClient
macOS, Linux, Solaris, AIX - <Tanium Client>/taniumclient
macOS, Linux - <Tanium Client>/distribute-tools.sh
macOS, Linux - <Tanium Client>/TaniumCX
Windows - <Tanium Client>\\TaniumClient.exe
Windows - <Tanium Client>\\TaniumCX.exe'
  impact 0.5
  ref 'DPMS Target Tanium 7.x Application on TanOS'
  tag check_id: 'C-58567r867760_chk'
  tag severity: 'medium'
  tag gid: 'V-254954'
  tag rid: 'SV-254954r867762_rule'
  tag stig_id: 'TANS-AP-001420'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-58511r867761_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
