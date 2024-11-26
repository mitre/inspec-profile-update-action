control 'SV-45115' do
  title 'Browser must retain history on exit.'
  desc 'Delete Browsing History on exit automatically deletes specified items when the last browser window closes.  Disabling this function will prevent users from deleting their browsing history, which could be used to identify malicious Web sites and files that could later be used for anti-virus and intrusion detection system (IDS) signatures.  Furthermore, preventing users from deleting browsing history could be used to identify abusive web surfing on government systems.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History -> "Allow deleting browsing history on exit" must be "Disabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Privacy 

Criteria: If the value ClearBrowsingHistoryOnExit is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History -> "Allow deleting browsing history on exit" to "Disabled".'
  impact 0.5
  ref 'DPMS Target IE Version 10'
  tag check_id: 'C-42470r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22148'
  tag rid: 'SV-45115r1_rule'
  tag stig_id: 'DTBI760'
  tag gtitle: 'DTBI760 - Browsing History on exit'
  tag fix_id: 'F-38511r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
