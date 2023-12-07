control 'SV-225563' do
  title 'The Force shutdown from a remote system user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Force shutdown from a remote system" user right can remotely shut down a system, which could result in a DoS.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Force shutdown from a remote system" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Force shutdown from a remote system" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27262r472031_chk'
  tag severity: 'medium'
  tag gid: 'V-225563'
  tag rid: 'SV-225563r852276_rule'
  tag stig_id: 'WN12-UR-000023'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27250r472032_fix'
  tag 'documentable'
  tag legacy: ['SV-53050', 'V-26488']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
