control 'SV-221204' do
  title 'Exchange must have accepted domains configured.'
  desc 'Exchange may be configured to accept email for multiple domain names. This setting identifies the domains for which the server will accept mail. This check verifies the email server is not accepting email for unauthorized domains.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine the Accepted Domain values.  

Open the Exchange Management Shell and enter the following command:
 
Get-AcceptedDomain | Select Name, DomainName, Identity, Default

If the value of "Default" is not set to "True", this is a finding.

or

If the "Default" value for "AcceptedDomains" is set to another value other than "True" and has signoff and risk acceptance in the EDSP, this is not a finding.'
  desc 'fix', "Update the EDSP.

Open the Exchange Management Shell and enter the following command:
 
Set-AcceptedDomain -Identity <'IdentityName'> -MakeDefault $true

Note: The <IdentityName> value must be in single quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Edge Transport Server'
  tag check_id: 'C-22919r411738_chk'
  tag severity: 'medium'
  tag gid: 'V-221204'
  tag rid: 'SV-221204r612603_rule'
  tag stig_id: 'EX16-ED-000030'
  tag gtitle: 'SRG-APP-000038'
  tag fix_id: 'F-22908r411739_fix'
  tag 'documentable'
  tag legacy: ['SV-95199', 'V-80489']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
