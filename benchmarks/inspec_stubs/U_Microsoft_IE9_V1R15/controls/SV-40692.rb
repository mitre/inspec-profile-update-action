control 'SV-40692' do
  title 'External branding feature of Internet Explorer must be disallowed .'
  desc 'Prevents branding of Internet programs, such as customization of Internet Explorer and Outlook Express logos and title bars, by another party. If you enable this policy, it prevents customization of the browser by another party, such as an Internet service provider or Internet content provider. If you disable this policy or do not configure it, users could install customizations from another party-for example, when signing up for Internet services. This policy is intended for administrators who want to maintain a consistent browser across an organization.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Disable external branding of Internet Explorer" must be “Enabled”. 

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKCU\\Software\\Policies\\Microsoft\\Internet Explorer\\Restrictions 

Criteria: If the value NoExternalBranding is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Disable external branding of Internet Explorer" to “Enabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39422r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15575'
  tag rid: 'SV-40692r1_rule'
  tag stig_id: 'DTBI695'
  tag gtitle: 'DTBI695 - External branding of Internet Explorer'
  tag fix_id: 'F-34550r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
