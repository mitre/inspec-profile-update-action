control 'SV-33487' do
  title 'Automatically configure user profile based on Active Directory primary SMTP address  must be enforced.'
  desc 'If a user is joined to a domain in an Active Directory environment and does not have an e-mail account configured, Outlook populates the e-mail address field of the New Account Wizard with the primary SMTP address of the user who is currently logged on to Active Directory. The user can change the address to configure a different account, or click Next to use the default settings from Active Directory. If users are allowed to change this address, they could incorrectly configure their environment or misrepresent their identity.'
  desc 'check', 'NOTE: If Outlook 2010 is configured to access DoD Enterprise Email, this check is not applicable.

The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> Exchange “Automatically configure profile based on Active Directory Primary SMTP address” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\autodiscover

Criteria: If the value ZeroConfigExchange is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> Exchange “Automatically configure profile based on Active Directory Primary SMTP address” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33971r2_chk'
  tag severity: 'medium'
  tag gid: 'V-17736'
  tag rid: 'SV-33487r2_rule'
  tag stig_id: 'DTOO278 - Outlook'
  tag gtitle: 'DTOO278 - Auto configure profile based on AD'
  tag fix_id: 'F-29659r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
