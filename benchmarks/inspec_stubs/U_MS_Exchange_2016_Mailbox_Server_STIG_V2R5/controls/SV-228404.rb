control 'SV-228404' do
  title 'Exchange Outlook Anywhere clients must use NTLM authentication to access email.'
  desc 'Identification and authentication provide the foundation for access control. Access to email services applications require NTLM authentication. Outlook Anywhere, if authorized for use by the site, must use NTLM authentication when accessing email.

Note: There is a technical restriction in Exchange Outlook Anywhere that requires a direct SSL connection from Outlook to the Certificate Authority (CA) server. There is also a constraint where Microsoft supports that the CA server must participate in the Active Director (AD) domain inside the enclave. For this reason, Outlook Anywhere must be deployed only for enclave-sourced Outlook users.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-OutlookAnywhere

Get-OutlookAnywhere | Select Name, Identity, InternalClientAuthenticationMethod, ExternalClientAuthenticationMethod

If the value of "InternalClientAuthenticationMethod" and the value of "ExternalClientAuthenticationMethod" are not set to NTLM, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

For InternalClientAuthenticationMethod:

Set-OutlookAnywhere -Identity '<IdentityName'> -InternalClientAuthenticationMethod NTLM

For ExternalClientAuthenticationMethod:

Set-OutlookAnywhere -Identity '<IdentityName'> -ExternalClientAuthenticationMethod NTLM"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30637r497008_chk'
  tag severity: 'medium'
  tag gid: 'V-228404'
  tag rid: 'SV-228404r879764_rule'
  tag stig_id: 'EX16-MB-000610'
  tag gtitle: 'SRG-APP-000391'
  tag fix_id: 'F-30622r497009_fix'
  tag 'documentable'
  tag legacy: ['SV-95445', 'V-80735']
  tag cci: ['CCI-001953']
  tag nist: ['IA-2 (12)']
end
