control 'SV-205449' do
  title 'The Mainframe Product must automatically audit account disabling actions.'
  desc 'When application accounts are disabled, user accessibility is affected. Accounts are used for identifying individual application users or for identifying the application processes themselves. In order to detect and respond to events affecting user accessibility and application processing, applications must audit account disabling actions and, as required, notify the appropriate individuals, so they can investigate the event. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/audit mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine account management settings.

If the Mainframe Product does not automatically audit account disabling actions, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to automatically audit account disabling actions.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5715r299580_chk'
  tag severity: 'medium'
  tag gid: 'V-205449'
  tag rid: 'SV-205449r395490_rule'
  tag stig_id: 'SRG-APP-000028-MFP-000041'
  tag gtitle: 'SRG-APP-000028'
  tag fix_id: 'F-5715r299581_fix'
  tag 'documentable'
  tag legacy: ['SV-82631', 'V-68141']
  tag cci: ['CCI-001404']
  tag nist: ['AC-2 (4)']
end
