control 'SV-253489' do
  title 'The "Create symbolic links" user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create symbolic links" user right can create pointers to other objects, which could potentially expose the system to attack.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Create symbolic links" user right, this is a finding:

Administrators

If the workstation has an approved use of Hyper-V, such as being used as a dedicated admin workstation using Hyper-V to separate administration and standard user functions, "NT VIRTUAL MACHINES\\VIRTUAL MACHINE" may be assigned this user right and is not a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create symbolic links" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56942r829549_chk'
  tag severity: 'medium'
  tag gid: 'V-253489'
  tag rid: 'SV-253489r829551_rule'
  tag stig_id: 'WN11-UR-000060'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-56892r829550_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
