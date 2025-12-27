control 'SV-223126' do
  title 'Browser must retain history on exit.'
  desc 'Delete Browsing History on exit automatically deletes specified items when the last browser window closes.  Disabling this function will prevent users from deleting their browsing history, which could be used to identify malicious websites and files that could later be used for anti-virus and Intrusion Detection System (IDS) signatures.  Furthermore, preventing users from deleting browsing history could be used to identify abusive web surfing on government systems.'
  desc 'check', %q(The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History -> 'Allow deleting browsing history on exit' must be 'Disabled'. Procedure: Use the Windows Registry Editor to navigate to the following key: HKLM\Software\Policies\Microsoft\Internet Explorer\Privacy Criteria: If the value "ClearBrowsingHistoryOnExit" is REG_DWORD = 0, this is not a finding.)
  desc 'fix', "Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> Delete Browsing History -> 'Allow deleting browsing history on exit' to 'Disabled'."
  impact 0.5
  ref 'DPMS Target Microsoft Internet Explorer 11'
  tag check_id: 'C-24799r428928_chk'
  tag severity: 'medium'
  tag gid: 'V-223126'
  tag rid: 'SV-223126r428930_rule'
  tag stig_id: 'DTBI760-IE11'
  tag gtitle: 'SRG-APP-000089'
  tag fix_id: 'F-24787r428929_fix'
  tag 'documentable'
  tag legacy: ['SV-59695', 'V-46829']
  tag cci: ['CCI-000169']
  tag nist: ['AU-12 a']
end
