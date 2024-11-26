control 'SV-205531' do
  title 'The Mainframe Product must notify system programmers and security administrators when accounts are created.'
  desc 'Once an attacker establishes access to an application, the attacker often attempts to create a persistent method of re-establishing access. One way to accomplish this is for the attacker to simply create a new account. Sending notification of account creation events to the system administrator (SA) and Information Security System Officer (ISSO) is one method for mitigating this risk.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/auditing mechanisms that meet or exceed access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine account management settings. 

If the Mainframe Product does not notify system programmers and security administrators when accounts are created, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to notify system programmers and security administrators when accounts are created.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5797r299826_chk'
  tag severity: 'medium'
  tag gid: 'V-205531'
  tag rid: 'SV-205531r397885_rule'
  tag stig_id: 'SRG-APP-000291-MFP-000043'
  tag gtitle: 'SRG-APP-000291'
  tag fix_id: 'F-5797r299827_fix'
  tag 'documentable'
  tag legacy: ['SV-82635', 'V-68145']
  tag cci: ['CCI-001683']
  tag nist: ['AC-2 (4)']
end
