control 'SV-25072' do
  title 'The system is not configured to use Safe DLL search mode.'
  desc 'The default search behavior, when an application calls a function in a Dynamic Link Library (DLL), is to search the current directory followed by the directories contained in the systems path environment variable.  An unauthorized DLL, inserted into an applications working directory, could allow malicious code to be run on the system.  Setting this policy value forces the system to search the %Systemroot% for the DLL before searching the current directory or the rest of the path.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

If the value for “MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)” is not set to “Enabled”, then this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \\System\\CurrentControlSet\\Control\\Session Manager\\

Value Name:  SafeDllSearchMode

Value Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-221r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3479'
  tag rid: 'SV-25072r1_rule'
  tag gtitle: 'Safe DLL Search Mode'
  tag fix_id: 'F-5699r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
