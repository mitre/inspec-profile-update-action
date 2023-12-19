control 'SV-84391' do
  title 'Exchange Outlook Anywhere (OA) clients must use NTLM authentication to access email.'
  desc 'Identification and authentication provide the foundation for access control. Access to email services applications requires NTLM authentication. Outlook Anywhere, if authorized for use by the site, must use NTLM authentication when accessing email.

Note: There is a technical restriction in Exchange OA that requires a direct SSL connection from Outlook to the CA server. There is also a constraint where Microsoft supports that the CA server must participate in the AD domain inside the enclave. For this reason, Outlook Anywhere must be deployed only for enclave-sourced Outlook users.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-OutlookAnywhere | Select Name, Identity, InternalClientAuthenticationMethod, ExternalClientAuthenticationMethod

If the value of InternalClientAuthenticationMethod and the value of ExternalClientAuthenticationMethod is not set to NTLM, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following commands:

For InternalClientAuthenticationMethod:

Set-OutlookAnywhere -Identity '<IdentityName'> -InternalClientAuthenticationMethod NTLM

For ExternalClientAuthenticationMethod:

Set-OutlookAnywhere -Identity '<IdentityName'> -ExternalClientAuthenticationMethod NTLM"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70219r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69769'
  tag rid: 'SV-84391r1_rule'
  tag stig_id: 'EX13-CA-000135'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-75981r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
