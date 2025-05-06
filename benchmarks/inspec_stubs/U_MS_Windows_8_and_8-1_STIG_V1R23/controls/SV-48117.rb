control 'SV-48117' do
  title 'The system must be configured to use Safe DLL Search Mode.'
  desc "The default search behavior, when an application calls a function in a Dynamic Link Library (DLL), is to search the current directory, followed by the directories contained in the system's path environment variable.  An unauthorized DLL, inserted into an application's working directory, could allow malicious code to be run on the system.  Setting this policy value forces the system to search the %Systemroot% for the DLL before searching the current directory or the rest of the path."
  desc 'check', %q(Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.)  
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies -> Security Options.

(See "Updating the Windows Security Options File" in the STIG Overview document if MSS settings are not visible in the system's policy tools.)

If the value for "MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)" is not set to "Enabled", this is a finding. 

The policy referenced configures the following registry value:

Registry Hive: HKEY_LOCAL_MACHINE 
Registry Path: \System\CurrentControlSet\Control\Session Manager\

Value Name: SafeDllSearchMode

Value Type: REG_DWORD
Value: 1)
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> "MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44843r1_chk'
  tag severity: 'medium'
  tag gid: 'V-3479'
  tag rid: 'SV-48117r1_rule'
  tag stig_id: 'WN08-SO-000045'
  tag gtitle: 'Safe DLL Search Mode'
  tag fix_id: 'F-41254r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
