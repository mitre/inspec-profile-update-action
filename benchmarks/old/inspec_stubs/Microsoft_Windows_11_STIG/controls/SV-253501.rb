control 'SV-253501' do
  title 'The "Manage auditing and security log" user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Manage auditing and security log" user right can manage the security log and change auditing configurations. This could be used to clear evidence of tampering.

'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Manage auditing and security log" user right, this is a finding:

Administrators

If the organization has an "Auditors" group the assignment of this group to the user right would not be a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Manage auditing and security log" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56954r829585_chk'
  tag severity: 'medium'
  tag gid: 'V-253501'
  tag rid: 'SV-253501r829587_rule'
  tag stig_id: 'WN11-UR-000130'
  tag gtitle: 'SRG-OS-000057-GPOS-00027'
  tag fix_id: 'F-56904r829586_fix'
  tag satisfies: ['SRG-OS-000057-GPOS-00027', 'SRG-OS-000063-GPOS-00032']
  tag 'documentable'
  tag cci: ['CCI-000162', 'CCI-000171']
  tag nist: ['AU-9 a', 'AU-12 b']
end
