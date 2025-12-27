control 'SV-47844' do
  title 'Local administrator accounts on domain systems must not share the same password.'
  desc 'Local administrator accounts on domain systems must use unique passwords. In the event a domain system is compromised, sharing the same password for local administrator accounts on domain systems will allow an attacker to move laterally and compromise multiple domain systems.'
  desc 'check', %q(Verify local administrator accounts on domain systems are using unique passwords. If local administrator accounts on domain systems are sharing a password, this is a finding.

Microsoft's Local Administrator Password Solution (LAPS) provides an automated solution for maintaining and regularly changing a local administrator password for domain-joined systems. LAPS can manage a single local administrator account. The default is the built-in administrator account however it can be configured to manage an administrator account of a different name. If additional local administrator accounts exist across systems, the organization must have a process to require unique passwords on each system for the additional accounts.

Other automated solutions that provide this capability may also be used.

If LAPS has been installed and enabled in the domain, the following PowerShell query will return a list of systems that do not have a local administrator password managed by LAPS. (The LAPS PowerShell module requires PowerShell 2.0 or higher and .NET Framework 4.0.)

Open "Windows PowerShell".
If the LAPS PowerShell module has not been previously imported, execute the following first: "Import-Module AdmPwd.ps".
Execute "Get-AdmPwdPassword -ComputerName * | Where-object {$_.password -eq $null}"

Review the returned list for validity.

Exclude computers with "OU=Domain Controllers" in the DistinguishedName field.  Other possible exceptions include but are not limited to non-Windows computers in Active Directory.

If any active/deployed Windows systems that are not managed by another process to ensure unique passwords for local administrator accounts are listed, this is a finding.

If the query fails, the organization must demonstrate that passwords for local administrator accounts are properly managed to ensure unique passwords for each.  If not, this is a finding.)
  desc 'fix', "Set unique passwords for all local administrator accounts on domain systems. 

Microsoft's Local Administrator Password Solution (LAPS) provides an automated solution for maintaining and regularly changing a local administrator password for domain-joined systems. If additional local administrator accounts exist across systems, the organization must have a process to require unique passwords on each system for the additional accounts.

Other automated solutions that provide this capability may also be used.

See Microsoft Security Advisory 3062591 for additional information and download of LAPS.
https://technet.microsoft.com/en-us/library/security/3062591.aspx"
  impact 0.5
  ref 'DPMS Target Active Directory Domain'
  tag check_id: 'C-80953r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36438'
  tag rid: 'SV-47844r5_rule'
  tag stig_id: 'AD.0008'
  tag gtitle: 'Unique Passwords for all Local Administrator Accounts'
  tag fix_id: 'F-85799r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001941']
  tag nist: ['IA-2 (8)']
end
