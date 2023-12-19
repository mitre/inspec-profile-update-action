control 'SV-33476' do
  title 'Access to updates, add-ins, and patches on Office.com must be disabled.'
  desc 'Having access to updates, add-ins, and patches on the Office Online Web site can help users ensure computers are up to date and equipped with the latest security patches. However, to ensure updates are tested and applied in a consistent manner, many organizations prefer to roll out updates using a centralized mechanism such as Microsoft Systems Center or Windows Server Update Services.
By default, users are allowed to download updates, add-ins, and patches from the Office Online Web site to keep their Office applications running smoothly and securely. If your organization has policies that govern the use of external resources such as Office Online, allowing users to download updates might cause them to violate these policies.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools \\ Options \\ General \\ Web Options... “Disable access to updates, add-ins, and patches on Office.com” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\internet

Criteria: If the value DisableDownloadCenterAccess is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Tools \\ Options \\ General \\ Web Options... “Disable access to updates, add-ins, and patches on Office.com” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33959r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17588'
  tag rid: 'SV-33476r1_rule'
  tag stig_id: 'DTOO177 - Office System'
  tag gtitle: 'DTOO177-Disable Updates from Office Online Site'
  tag fix_id: 'F-29648r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
