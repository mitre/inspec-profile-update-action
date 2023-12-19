control 'SV-225565' do
  title 'The Impersonate a client after authentication user right must only be assigned to Administrators, Service, Local Service, and Network Service.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Impersonate a client after authentication" user right allows a program to impersonate another user or account to run on their behalf.  An attacker could potentially use this to elevate privileges.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Impersonate a client after authentication" user right, this is a finding:

Administrators
Service
Local Service
Network Service

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN12-00-000010) and required frequency of changes (WN12-00-000011).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Impersonate a client after authentication" to only include the following accounts or groups:

Administrators
Service
Local Service
Network Service'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27264r472037_chk'
  tag severity: 'medium'
  tag gid: 'V-225565'
  tag rid: 'SV-225565r569185_rule'
  tag stig_id: 'WN12-UR-000025'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-27252r472038_fix'
  tag 'documentable'
  tag legacy: ['SV-52117', 'V-26490']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
