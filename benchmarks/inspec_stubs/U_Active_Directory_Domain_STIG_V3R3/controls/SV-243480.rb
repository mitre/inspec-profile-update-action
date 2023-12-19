control 'SV-243480' do
  title 'The domain functional level must be at a Windows Server version still supported by Microsoft.'
  desc 'Domains operating at functional levels below Windows Server versions no longer supported by Microsoft reduce the level of security in the domain and forest as advanced features of the directory are not available.  This also prevents the addition of domain controllers to the domain using Windows Server versions prior to the current domain functional level.'
  desc 'check', 'Open "Active Directory Domains and Trusts" (run "domain.msc") or "Active Directory Users and Computers" (run "dsa.msc").
Right click in the left pane on the name of the Domain being reviewed.
Select "Raise domain functional level..."
The current domain functional level will be displayed (as well as the option to raise the domain functional level).
Select "Cancel" to exit.

Alternately, using PowerShell (Windows 2008 R2 or later).
Select "Active Directory Module for Windows PowerShell", available in Administrative Tools or the Start Screen.
Run "Get-ADDomain".
View the value for "DomainMode:"

If the domain functional level is not Windows Server 2008 or later, this is a finding.

Using the highest domain functional level supported by the domain controllers is recommended.'
  desc 'fix', 'Raise the domain functional level to Windows Server 2008 or later.  Using the highest domain functional level supported by the domain controllers is recommended.

Raising the domain functional level needs to be carefully planned and implemented.  This prevents the addition of domain controllers to the domain using Windows versions prior to the current domain functional level. 

See Microsoft documentation for the process and requirements of raising the domain functional level.'
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46755r723562_chk'
  tag severity: 'medium'
  tag gid: 'V-243480'
  tag rid: 'SV-243480r723563_rule'
  tag stig_id: 'AD.0160'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-46712r723474_fix'
  tag 'documentable'
  tag legacy: ['V-8551', 'SV-9048']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
