control 'SV-226399' do
  title 'Unauthorized accounts must not have the Add workstations to domain user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

Accounts with the "Add workstations to domain" right may add computers to a domain.  This could result in unapproved or incorrectly configured systems being added to a domain.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.
Run "gpedit.msc".

Navigate to Local Computer Policy -> Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Add workstations to domain" right, this is a finding:

Administrators'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Add workstations to domain" to only include the following accounts or groups:

Administrators'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28102r477043_chk'
  tag severity: 'medium'
  tag gid: 'V-226399'
  tag rid: 'SV-226399r794670_rule'
  tag stig_id: 'WN12-UR-000044-DC'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-28090r477044_fix'
  tag 'documentable'
  tag legacy: ['SV-51143', 'V-30016']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
