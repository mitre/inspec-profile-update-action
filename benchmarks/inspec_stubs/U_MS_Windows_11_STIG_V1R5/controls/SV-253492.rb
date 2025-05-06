control 'SV-253492' do
  title 'The "Deny log on as a batch job" user right on domain-joined workstations must be configured to prevent access from highly privileged domain accounts.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a batch job" right defines accounts that are prevented from logging on to the system as a batch job, such as Task Scheduler.

In an Active Directory Domain, denying logons to the Enterprise Admins and Domain Admins groups on lower trust systems helps mitigate the risk of privilege escalation from credential theft attacks which could lead to the compromise of an entire domain.'
  desc 'check', 'This requirement is applicable to domain-joined systems, for standalone systems this is NA.

Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If the following groups or accounts are not defined for the "Deny log on as a batch job" right, this is a finding:

Domain Systems Only:
Enterprise Admin Group
Domain Admin Group'
  desc 'fix', 'This requirement is applicable to domain-joined systems, for standalone systems this is NA.

Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Deny log on as a batch job" to include the following:

Domain Systems Only:
Enterprise Admin Group
Domain Admin Group'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56945r829558_chk'
  tag severity: 'medium'
  tag gid: 'V-253492'
  tag rid: 'SV-253492r829560_rule'
  tag stig_id: 'WN11-UR-000075'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-56895r829559_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
