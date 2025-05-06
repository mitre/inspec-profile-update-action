control 'SV-207327' do
  title 'Exchange Outlook Anywhere (OA) clients must use NTLM authentication to access email.'
  desc 'Identification and authentication provide the foundation for access control. Access to email services applications require NTLM authentication. Outlook Anywhere, if authorized for use by the site, must use NTLM authentication when accessing email.

Note: There is a technical restriction in Exchange OA that requires a direct SSL connection from Outlook to the CA server. There is also a constraint where Microsoft supports that the CA server must participate in the AD domain inside the enclave. For this reason, Outlook Anywhere must be deployed only for enclave-sourced Outlook users.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-OutlookAnywhere

Get-OutlookAnywhere | Select Name, Identity, InternalClientAuthenticationMethod, ExternalClientAuthenticationMethod

If the value of InternalClientAuthenticationMethod and the value of ExternalClientAuthenticationMethod is not set to NTLM, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

For InternalClientAuthenticationMethod:

Set-OutlookAnywhere -Identity '<IdentityName'> -InternalClientAuthenticationMethod NTLM

For ExternalClientAuthenticationMethod:

Set-OutlookAnywhere -Identity '<IdentityName'> -ExternalClientAuthenticationMethod NTLM"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7585r393494_chk'
  tag severity: 'medium'
  tag gid: 'V-207327'
  tag rid: 'SV-207327r615936_rule'
  tag stig_id: 'EX13-MB-000305'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-7585r393495_fix'
  tag 'documentable'
  tag legacy: ['SV-84697', 'V-70075']
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
