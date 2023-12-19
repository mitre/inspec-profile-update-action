control 'SV-33486' do
  title 'Authentication with Exchange Server must be required.'
  desc 'Exchange Server supports the Kerberos authentication protocol and NTLM for authentication. The Kerberos protocol is the more secure authentication method and is supported on Windows 2000 Server and later versions. NTLM authentication is supported in pre-Windows 2000 environments.
By default, Outlook will attempt to authenticate using the Kerberos authentication protocol, if it cannot (because no Windows 2000 or later domain controllers are available), it will authenticate using NTLM.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> Exchange “Authentication with Exchange Server” must be set to “Enabled (Kerberos/NTLM Password Authentication)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value AuthenticationService is REG_DWORD = 9, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> Exchange “Authentication with Exchange Server” to “Enabled (Kerberos/NTLM Password Authentication)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33970r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17734'
  tag rid: 'SV-33486r1_rule'
  tag stig_id: 'DTOO280 - Outlook'
  tag gtitle: 'DTOO280 - Authentication w/Exchange Svr'
  tag fix_id: 'F-29658r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
