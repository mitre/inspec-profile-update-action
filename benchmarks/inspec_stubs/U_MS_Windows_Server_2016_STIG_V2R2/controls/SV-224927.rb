control 'SV-224927' do
  title 'Printing over HTTP must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature. Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and will prevent uncontrolled updates to the system.

This setting prevents the client computer from printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows NT\\Printers\\

Value Name: DisableHTTPPrinting

Type: REG_DWORD
Value: 0x00000001 (1)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> System >> Internet Communication Management >> Internet Communication settings >> "Turn off printing over HTTP" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26618r465683_chk'
  tag severity: 'medium'
  tag gid: 'V-224927'
  tag rid: 'SV-224927r569186_rule'
  tag stig_id: 'WN16-CC-000170'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-26606r465684_fix'
  tag 'documentable'
  tag legacy: ['SV-88181', 'V-73529']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
