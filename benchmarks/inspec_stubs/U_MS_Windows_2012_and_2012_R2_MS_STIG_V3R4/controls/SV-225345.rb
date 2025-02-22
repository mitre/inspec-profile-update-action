control 'SV-225345' do
  title 'Printing over HTTP must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents the client computer from printing over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Printers\\

Value Name: DisableHTTPPrinting

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off printing over HTTP" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27044r471377_chk'
  tag severity: 'medium'
  tag gid: 'V-225345'
  tag rid: 'SV-225345r569185_rule'
  tag stig_id: 'WN12-CC-000039'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27032r471378_fix'
  tag 'documentable'
  tag legacy: ['V-14259', 'SV-52997']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
