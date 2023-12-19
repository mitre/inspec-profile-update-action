control 'SV-234034' do
  title 'The vulnerability scanning application must implement privileged access authorization to all Tanium information systems and infrastructure components for selected organization-defined vulnerability scanning activities.'
  desc 'In certain situations, the nature of the vulnerability scanning may be more intrusive, or the information system component that is the subject of the scanning may contain highly sensitive information. Privileged access authorization to selected system components facilitates more thorough vulnerability scanning and also protects the sensitive nature of such scanning.

The vulnerability scanning application must utilize privileged access authorization for the scanning account.'
  desc 'check', 'Consult with the Tanium System Administrator to review the documented list of Tanium users.

If any users have access to Tanium Comply and are not on the list of documented users, this is a finding.

If Tanium Comply is not installed, this check is Not Applicable.'
  desc 'fix', 'Prepare and maintain documentation identifying the Tanium Comply users and their respective User Roles and AD security groups.'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37219r610602_chk'
  tag severity: 'medium'
  tag gid: 'V-234034'
  tag rid: 'SV-234034r612749_rule'
  tag stig_id: 'TANS-00-000755'
  tag gtitle: 'SRG-APP-000414'
  tag fix_id: 'F-37184r610603_fix'
  tag 'documentable'
  tag legacy: ['SV-102141', 'V-92039']
  tag cci: ['CCI-001067']
  tag nist: ['RA-5 (5)']
end
