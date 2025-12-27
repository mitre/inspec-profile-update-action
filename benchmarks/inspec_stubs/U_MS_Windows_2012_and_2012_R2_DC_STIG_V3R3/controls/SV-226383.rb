control 'SV-226383' do
  title 'The Deny log on as a service user right must be configured to include no accounts or groups (blank) on domain controllers.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Deny log on as a service" user right defines accounts that are denied log on as a service.  

Incorrect configurations could prevent services from starting and result in a DoS.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups are defined for the "Deny log on as a service" user right, this is a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Deny log on as a service" to include no entries (blank).'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28086r476995_chk'
  tag severity: 'medium'
  tag gid: 'V-226383'
  tag rid: 'SV-226383r794628_rule'
  tag stig_id: 'WN12-UR-000019-DC'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-28074r476996_fix'
  tag 'documentable'
  tag legacy: ['V-26484', 'SV-51146']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
