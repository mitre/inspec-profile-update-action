control 'SV-225557' do
  title 'The Deny access to this computer from the network user right on member servers must be configured to prevent access from highly privileged domain accounts and local accounts on domain systems, and from unauthenticated access on all systems.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny access to this computer from the network" user right defines the accounts that are prevented from logging on from the network.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Local accounts on domain-joined systems must also be assigned this right to decrease the risk of lateral movement resulting from credential theft attacks.

The Guests group must be assigned this right to prevent unauthenticated access.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny access to this computer from the network" user right, this is a finding:

Domain Systems Only:
Enterprise Admins group
Domain Admins group
"Local account and member of Administrators group" or "Local account" (see Note below)

All Systems:
Guests group

Note: Windows Server 2012 R2 added new built-in security groups, "Local account" and "Local account and member of Administrators group". "Local account" is more restrictive but may cause issues on servers such as systems that provide Failover Clustering.
Microsoft Security Advisory Patch 2871997 adds the new security groups to Windows Server 2012.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny access to this computer from the network" to include the following:

Domain Systems Only:
Enterprise Admins group
Domain Admins group
"Local account and member of Administrators group" or "Local account" (see Note below)

All Systems:
Guests group

Note: Windows Server 2012 R2 added new built-in security groups, "Local account" and "Local account and member of Administrators group". "Local account" is more restrictive but may cause issues on servers such as systems that provide Failover Clustering.
Microsoft Security Advisory Patch 2871997 adds the new security groups to Windows Server 2012.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27256r472013_chk'
  tag severity: 'medium'
  tag gid: 'V-225557'
  tag rid: 'SV-225557r569185_rule'
  tag stig_id: 'WN12-UR-000017-MS'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-27244r472014_fix'
  tag 'documentable'
  tag legacy: ['SV-51501', 'V-1155']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
