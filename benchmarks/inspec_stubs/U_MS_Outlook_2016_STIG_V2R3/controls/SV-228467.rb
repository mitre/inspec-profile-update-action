control 'SV-228467' do
  title 'Outlook must be configured to force authentication when connecting to an Exchange server.'
  desc 'This policy setting controls which authentication method Outlook uses to authenticate with Microsoft Exchange Server. Note - Exchange Server supports the Kerberos authentication protocol and NTLM for authentication. The Kerberos protocol is the more secure authentication method and is supported on Windows 2000 Server and later versions. NTLM authentication is supported in pre-Windows 2000 environments. If you enable this policy setting, you can choose from three different options for controlling how Outlook authenticates with Microsoft Exchange Server:- Kerberos/NTLM password authentication. Outlook attempts to authenticate using the Kerberos authentication protocol. If this attempt fails, Outlook attempts to authenticate using NTLM. This option is the default configuration.- Kerberos password authentication. Outlook attempts to authenticate using the Kerberos protocol only.- NTLM password authentication. Outlook attempts to authenticate using NTLM only. If you disable or do not configure this policy setting, Outlook will attempt to authenticate using the Kerberos authentication protocol. If it cannot (because no Windows 2000 or later domain controllers are available), it will authenticate using NTLM.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Account Settings -> Exchange "Authentication with Exchange Server" is set to "Enabled (Kerberos Password Authentication)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value AuthenticationService is REG_DWORD = 16 (decimal) or 10 (hex), this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Account Settings -> Exchange "Authentication with Exchange Server" to "Enabled (Kerberos Password Authentication)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30700r497723_chk'
  tag severity: 'medium'
  tag gid: 'V-228467'
  tag rid: 'SV-228467r508021_rule'
  tag stig_id: 'DTOO280'
  tag gtitle: 'SRG-APP-000395'
  tag fix_id: 'F-30685r497724_fix'
  tag 'documentable'
  tag legacy: ['SV-85879', 'V-71255']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
