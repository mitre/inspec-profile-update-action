control 'SV-3479' do
  title 'The system is not configured to use Safe DLL Search Mode.'
  desc 'The default search behavior, when an application calls a function in a Dynamic Link Library (DLL), is to search the current directory followed by the directories contained in the systems path environment variable.  An unauthorized DLL inserted into an applications working directory could allow malicious code to be run on the system.  Creating the following registry key and setting the appropriate value forces the system to search the %Systemroot% for the DLL before searching the current directory or the rest of the path.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> “MSS: (SafeDllSearchMode) Enable Safe DLL search mode (recommended)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-3479'
  tag rid: 'SV-3479r1_rule'
  tag gtitle: 'Safe DLL Search Mode'
  tag fix_id: 'F-5699r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
