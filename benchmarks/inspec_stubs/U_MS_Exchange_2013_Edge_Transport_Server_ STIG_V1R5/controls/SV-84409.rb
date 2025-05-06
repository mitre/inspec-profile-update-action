control 'SV-84409' do
  title 'Exchange must have accepted domains configured.'
  desc 'Exchange may be configured to accept email for multiple domain names. This setting identifies the domains for which the server will accept mail. This check verifies the email server is not accepting email for unauthorized domains.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the Accepted Domain values.  

Open the Exchange Management Shell and enter the following command:
 
Get-AcceptedDomain | Select Name, DomainName, Identity, Default

If the Default value is not set to True, this is a finding.

or

If the Default value for AcceptedDomains is set to another value other than True and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Update the EDSP.

Open the Exchange Management Shell and enter the following command:
 
Set-AcceptedDomain -Identity <'IdentityName'> -MakeDefault $true

Note: The <IdentityName> value must be in quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70239r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69787'
  tag rid: 'SV-84409r1_rule'
  tag stig_id: 'EX13-EG-000015'
  tag gtitle: 'SRG-APP-000038'
  tag fix_id: 'F-75999r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
