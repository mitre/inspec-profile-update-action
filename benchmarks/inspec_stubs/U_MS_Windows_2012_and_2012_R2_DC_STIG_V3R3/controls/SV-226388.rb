control 'SV-226388' do
  title 'The Generate security audits user right must only be assigned to Local Service and Network Service.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Generate security audits" user right specifies users and processes that can generate Security Log audit records, which must only be the system service accounts defined.'
  desc 'check', 'Verify the effective setting in Local Group Policy Editor.

Run "gpedit.msc".

Navigate to Local Computer Policy >> Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Generate security audits" user right, this is a finding:

Local Service
Network Service

If an application requires this user right, this would not be a finding.

Vendor documentation must support the requirement for having the user right.

The requirement must be documented with the ISSO.

The application account must meet requirements for application account passwords, such as length (WN12-00-000010) and required frequency of changes (WN12-00-000011).'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Generate security audits" to only include the following accounts or groups:

Local Service
Network Service'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-28091r477010_chk'
  tag severity: 'medium'
  tag gid: 'V-226388'
  tag rid: 'SV-226388r794660_rule'
  tag stig_id: 'WN12-UR-000024'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-28079r477011_fix'
  tag 'documentable'
  tag legacy: ['SV-52116', 'V-26489']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
