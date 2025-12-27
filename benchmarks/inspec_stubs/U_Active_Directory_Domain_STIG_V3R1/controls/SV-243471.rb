control 'SV-243471' do
  title 'Local administrator accounts on domain systems must not share the same password.'
  desc 'Local administrator accounts on domain systems must use unique passwords. In the event a domain system is compromised, sharing the same password for local administrator accounts on domain systems will allow an attacker to move laterally and compromise multiple domain systems.'
  desc 'check', %q(Verify local administrator accounts on domain systems are using unique passwords. If local administrator accounts on domain systems are sharing a password, this is a finding.

It is highly recommended to use Microsoft's Local Administrator Password Solution (LAPS), which provides an automated solution for maintaining and regularly changing a local administrator password for domain-joined systems. LAPS can manage a single local administrator account. The default is the built-in administrator account; however, it can be configured to manage an administrator account of a different name. If additional local administrator accounts exist across systems, the organization must have a process to require unique passwords on each system for the additional accounts.

The AO may approve other automated solutions that provide this capability.

If LAPS has been installed and enabled in the domain, the following PowerShell query will return a list of systems that do not have a local administrator password managed by LAPS. (The LAPS PowerShell module requires PowerShell 2.0 or higher and .NET Framework 4.0.)

Open "Windows PowerShell".
If the LAPS PowerShell module has not been previously imported, execute the following first: "Import-Module AdmPwd.ps".
Execute "Get-AdmPwdPassword -ComputerName * | Where-object {$_.password -eq $null}"

Review the returned list for validity.

Exclude computers with "OU=Domain Controllers" in the DistinguishedName field.  Other possible exceptions include but are not limited to non-Windows computers in Active Directory.

If any active/deployed Windows systems that are not managed by another process to ensure unique passwords for local administrator accounts are listed, this is a finding.

If the query fails, the organization must demonstrate that passwords for local administrator accounts are properly managed to ensure unique passwords for each. If not, this is a finding.)
  desc 'fix', "Set unique passwords for all local administrator accounts on domain systems. 

It is highly recommended to use Microsoft's LAPS, which provides an automated solution for maintaining and regularly changing a local administrator password for domain-joined systems. If additional local administrator accounts exist across systems, the organization must have a process to require unique passwords on each system for the additional accounts.

The AO may approve other automated solutions that provide this capability.

See Microsoft Security Advisory 3062591 for additional information and download of LAPS.
https://www.microsoft.com/en-us/download/details.aspx?id=46899"
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-46746r804649_chk'
  tag severity: 'medium'
  tag gid: 'V-243471'
  tag rid: 'SV-243471r804653_rule'
  tag stig_id: 'AD.0008'
  tag gtitle: 'SRG-OS-000112'
  tag fix_id: 'F-46703r804652_fix'
  tag 'documentable'
  tag legacy: ['V-36438', 'SV-47844']
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
