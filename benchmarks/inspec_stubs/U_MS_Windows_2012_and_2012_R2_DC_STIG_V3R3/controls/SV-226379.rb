control 'SV-226379' do
  title 'The Create symbolic links user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Create symbolic links" user right can create pointers to other objects, which could potentially expose the system to attack.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Create symbolic links" user right, this is a finding:

Administrators

Systems that have the Hyper-V role will also have "Virtual Machines" given this user right (this may be displayed as "NT Virtual Machine\\Virtual Machines").  This is not a finding.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Create symbolic links" to only include the following accounts or groups:

Administrators

Systems that have the Hyper-V role will also have "Virtual Machines" given this user right.  If this needs to be added manually, enter it as "NT Virtual Machine\\Virtual Machines".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28082r476983_chk'
  tag severity: 'medium'
  tag gid: 'V-226379'
  tag rid: 'SV-226379r794656_rule'
  tag stig_id: 'WN12-UR-000015'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-28070r476984_fix'
  tag 'documentable'
  tag legacy: ['SV-53054', 'V-26482']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
