control 'SV-253499' do
  title 'The "Load and unload device drivers" user right must only be assigned to the Administrators group.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Load and unload device drivers" user right allows device drivers to dynamically be loaded on a system by a user. This could potentially be used to install malicious code by an attacker.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any groups or accounts other than the following are granted the "Load and unload device drivers" user right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Load and unload device drivers" to only include the following groups or accounts:

Administrators'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56952r829579_chk'
  tag severity: 'medium'
  tag gid: 'V-253499'
  tag rid: 'SV-253499r877392_rule'
  tag stig_id: 'WN11-UR-000120'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-56902r829580_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
