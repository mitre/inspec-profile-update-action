control 'SV-226309' do
  title 'The system must be configured to use Safe DLL Search Mode.'
  desc "The default search behavior, when an application calls a function in a Dynamic Link Library (DLL), is to search the current directory, followed by the directories contained in the system's path environment variable.  An unauthorized DLL, inserted into an application's working directory, could allow malicious code to be run on the system.  Setting this policy value forces the system to search the %Systemroot% for the DLL before searching the current directory or the rest of the path."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Session Manager\\

Value Name: SafeDllSearchMode

Value Type: REG_DWORD
Value: 1'
  desc 'fix', %q(Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)" to "Enabled".

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.))
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28011r476771_chk'
  tag severity: 'medium'
  tag gid: 'V-226309'
  tag rid: 'SV-226309r569184_rule'
  tag stig_id: 'WN12-SO-000045'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27999r476772_fix'
  tag 'documentable'
  tag legacy: ['SV-52920', 'V-3479']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
