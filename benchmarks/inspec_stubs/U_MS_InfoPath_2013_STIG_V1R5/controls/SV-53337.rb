control 'SV-53337' do
  title 'Redirection behavior for upgraded web sites by SharePoint must be blocked.'
  desc 'InfoPath automatically redirects user requests for sites that have not been upgraded to the temporary URL if it is located on the local intranet, but blocks them if the temporary URL is located elsewhere. InfoPath will prompt users before redirecting forms or form templates to another intranet site.
If this restriction is relaxed, all requests to sites that have not been upgraded will be redirected to their targets, regardless of location. This functionality could cause requests made to a secure site to be redirected to an unsecured one (for example, requests to an intranet site could be redirected to an unencrypted Internet site), causing sensitive information to be at risk.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> Security -> "Control behavior for Microsoft SharePoint Foundation gradual upgrade" must be set to "Enabled (Block all redirections)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\InfoPath\\security

Criteria: If the value GradualUpgradeRedirection is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft InfoPath 2013 -> Security -> "Control behavior for Microsoft SharePoint Foundation gradual upgrade" to "Enabled (Block all redirections)".'
  impact 0.5
  ref 'DPMS Target Microsoft InfoPath 2013'
  tag check_id: 'C-47614r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17576'
  tag rid: 'SV-53337r1_rule'
  tag stig_id: 'DTOO157'
  tag gtitle: 'DTOO157 - SharePoint Services Gradual Upgrade'
  tag fix_id: 'F-46267r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
