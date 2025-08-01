control 'SV-223346' do
  title 'The Exchange client authentication with Exchange servers must be enabled to use Kerberos Password Authentication.'
  desc 'This policy setting controls which authentication method Outlook uses to authenticate with Microsoft Exchange Server. Note: Exchange Server supports the Kerberos authentication protocol and NTLM for authentication. The Kerberos protocol is the more secure authentication method and is supported on Windows 2000 Server and later versions. NTLM authentication is supported in pre-Windows 2000 environments.

If you enable this policy setting, you can choose from three different options for controlling how Outlook authenticates with Microsoft Exchange Server:

- Kerberos/NTLM password authentication. Outlook attempts to authenticate using the Kerberos authentication protocol. If this attempt fails, Outlook attempts to authenticate using NTLM. This option is the default configuration.
- Kerberos password authentication. Outlook attempts to authenticate using the Kerberos protocol only.
- NTLM password authentication. Outlook attempts to authenticate using NTLM only.

If you disable or do not configure this policy setting, Outlook will attempt to authenticate using the Kerberos authentication protocol. If it cannot (because no Windows 2000 or later domain controllers are available), it will authenticate using NTLM.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Account Settings >> Exchange >> Authentication with Exchange Server is set to Kerberos Password Authentication.
 
Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security!authenticationservice

If the value authenticationservice is set to REG_DWORD = 16 (decimal) or 10 (hex), this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Account Settings >> Exchange >> Authentication with Exchange Server to Kerberos Password Authentication.'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25019r442257_chk'
  tag severity: 'medium'
  tag gid: 'V-223346'
  tag rid: 'SV-223346r508019_rule'
  tag stig_id: 'O365-OU-000001'
  tag gtitle: 'SRG-APP-000575'
  tag fix_id: 'F-25007r442258_fix'
  tag 'documentable'
  tag legacy: ['SV-108871', 'V-99767']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
