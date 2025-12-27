control 'SV-54053' do
  title 'Outlook must be configured to force authentication when connecting to an Exchange server.'
  desc 'Exchange Server supports the Kerberos authentication protocol and NTLM for authentication. The Kerberos protocol is the more secure authentication method and is supported on Windows 2000 Server and later versions. NTLM authentication is supported in pre-Windows 2000 environments.
When authentication is enabled, Outlook will attempt to authenticate using the Kerberos authentication protocol, if it cannot (because no Windows 2000 or later domain controllers are available), it will authenticate using NTLM, ensuring a more secure authentication to the Exchange server.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Account Settings -> Exchange "Authentication with Exchange Server" is set to "Enabled (Kerberos/NTLM Password Authentication)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value AuthenticationService is REG_DWORD = 9, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Account Settings -> Exchange "Authentication with Exchange Server" to "Enabled (Kerberos/NTLM Password Authentication)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47993r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17734'
  tag rid: 'SV-54053r1_rule'
  tag stig_id: 'DTOO280'
  tag gtitle: 'DTOO280 - Authentication w/Exchange Svr'
  tag fix_id: 'F-46933r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
