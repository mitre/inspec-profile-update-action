control 'SV-44027' do
  title 'Outlook Anywhere (OA) clients must use NTLM authentication to access email.'
  desc 'Identification and Authentication provide the foundation for access control.  Access to email services applications require NTLM authentication.  Outlook Anywhere, if authorized for use by the site, must use NTLM authentication when accessing email.

Note: There is a technical restriction in Exchange OA that requires a direct SSL connection from Outlook to the CA server. There is also a constraint where Microsoft supports that the CA server must participate in the AD domain inside the enclave. For this reason, Outlook Anywhere must be deployed only for enclave-sourced Outlook users.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-OutlookAnywhere

If the value of 'Client Authentication Method' is not set to 'NTLM', this is a finding."
  desc 'fix', 'Open the Exchange Management Shell and enter the following command:

Set-OutlookAnywhere -ClientAuthenticationMethod NTLM'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41714r3_chk'
  tag severity: 'medium'
  tag gid: 'V-33607'
  tag rid: 'SV-44027r2_rule'
  tag stig_id: 'Exch-1-402'
  tag gtitle: 'Exch-1-402'
  tag fix_id: 'F-37499r2_fix'
  tag 'documentable'
end
