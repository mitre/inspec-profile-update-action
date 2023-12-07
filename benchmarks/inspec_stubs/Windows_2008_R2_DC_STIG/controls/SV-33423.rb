control 'SV-33423' do
  title 'Unauthorized accounts must not have the Generate security audits user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high-level capabilities.

The "Generate security audits" user right specifies users and processes that can generate Security Log audit records, which must only be the system service accounts defined.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.
Expand the Security Configuration and Analysis tree view.
Navigate to Local Policies >> User Rights Assignment.

If any accounts or groups other than the following are granted the "Generate security audits" user right, this is a finding:

Local Service
Network Service'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Windows Settings >> Security Settings >> Local Policies >> User Rights Assignment >> "Generate security audits" to only include the following accounts or groups:

Local Service
Network Service'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-61341r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26489'
  tag rid: 'SV-33423r2_rule'
  tag stig_id: 'WINUR-000024'
  tag gtitle: 'Generate security audits'
  tag fix_id: 'F-66033r2_fix'
  tag 'documentable'
  tag severity_override_guidance: 'If an application requires this user right, this can be downgraded to not a finding if the following conditions are met:
Vendor documentation must support the requirement for having the user right.
The requirement must be documented with the ISSO.
The application account must meet requirements for application account passwords, such as length and required changes frequency (V-14271).'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
