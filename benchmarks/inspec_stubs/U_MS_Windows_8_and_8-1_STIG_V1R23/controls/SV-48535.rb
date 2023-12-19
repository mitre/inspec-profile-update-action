control 'SV-48535' do
  title 'Unauthorized accounts must not have the Generate security audits user right.'
  desc 'Inappropriate granting of user rights can provide system, administrative, and other high level capabilities.

The "Generate security audits" user right specifies users and processes that can generate Security Log audit records, which must only be the system service accounts defined.'
  desc 'check', 'Analyze the system using the Security Configuration and Analysis snap-in.  (See "Performing Analysis with the Security Configuration and Analysis Snap-in" in the STIG Overview document.) 
Expand the Security Configuration and Analysis tree view. 
Navigate to Local Policies -> User Rights Assignment.

If any accounts or groups other than the following are granted the "Generate security audits" user right, this is a finding:

Local Service
Network Service'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> User Rights Assignment -> "Generate security audits" to only include the following accounts or groups:

Local Service
Network Service'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45185r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26489'
  tag rid: 'SV-48535r2_rule'
  tag stig_id: 'WN08-UR-000024'
  tag gtitle: 'Generate security audits'
  tag fix_id: 'F-41657r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECLP-1'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
