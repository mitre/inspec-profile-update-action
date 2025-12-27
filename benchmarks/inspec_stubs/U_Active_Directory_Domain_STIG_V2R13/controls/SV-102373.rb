control 'SV-102373' do
  title 'Domain-joined systems (excluding domain controllers) must not be configured for unconstrained delegation.'
  desc 'Unconstrained delegation enabled on a computer can allow the computer account to be impersonated without limitation. If delegation is required, it must be limited/constrained to the specific services and accounts required.'
  desc 'check', 'Open "Windows PowerShell" on a domain controller.

Enter "Get-ADComputer -Filter {(TrustedForDelegation -eq $True) -and (PrimaryGroupID -eq 515)} -Properties TrustedForDelegation, TrustedToAuthForDelegation, ServicePrincipalName, Description, PrimaryGroupID".

If any computers are returned, this is a finding. 
(TrustedForDelegation equaling True indicates unconstrained delegation.)

PrimaryGroupID 515 = Domain computers (excludes DCs)
TrustedForDelegation = Unconstrained Delegation
TrustedToAuthForDelegation = Constrained delegation
ServicePrincipalName = Service Names
Description = Computer Description'
  desc 'fix', 'Remove unconstrained delegation from computers in the domain. 

Select "Properties" for the computer object.

Select the "Delegation" tab.

De-select "Trust this computer for delegation to any service (Kerberos only)"

Configured constrained delegation for specific services where required.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-91557r1_chk'
  tag severity: 'medium'
  tag gid: 'V-92285'
  tag rid: 'SV-102373r1_rule'
  tag stig_id: 'AD.0018'
  tag gtitle: 'AD.0018'
  tag fix_id: 'F-98499r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
