control 'SV-225559' do
  title 'The Deny log on as a service user right on member servers must be configured to prevent access from highly privileged domain accounts on domain systems.  No other groups or accounts must be assigned this right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a service" user right defines accounts that are denied log on as a service.  

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower-trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.

Incorrect configurations could prevent services from starting and result in a DoS.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If the following accounts or groups are not defined for the "Deny log on as a service" user right on domain-joined systems, this is a finding:

Enterprise Admins Group
Domain Admins Group

If any accounts or groups are defined for the "Deny log on as a service" user right on non-domain-joined systems, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on as a service" to include the following for domain-joined systems:

Enterprise Admins Group
Domain Admins Group

Configure the "Deny log on as a service" for nondomain systems to include no entries (blank).'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27258r472019_chk'
  tag severity: 'medium'
  tag gid: 'V-225559'
  tag rid: 'SV-225559r569185_rule'
  tag stig_id: 'WN12-UR-000019-MS'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-27246r472020_fix'
  tag 'documentable'
  tag legacy: ['SV-51504', 'V-26484']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
