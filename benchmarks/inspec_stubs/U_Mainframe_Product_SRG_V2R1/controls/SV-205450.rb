control 'SV-205450' do
  title 'The Mainframe Product must automatically audit account removal actions.'
  desc 'When application accounts are removed, user accessibility is affected. Accounts are used for identifying individual application users or for identifying the application processes themselves. In order to detect and respond to events affecting user accessibility and application processing, applications must audit account removal actions and, as required, notify the appropriate individuals, so they can investigate the event. Such a capability greatly reduces the risk that application accessibility will be negatively affected for extended periods of time and provides logging that can be used for forensic purposes.

To address access requirements, many application developers choose to integrate their applications with enterprise-level authentication/access/audit mechanisms meeting or exceeding access control policy requirements. Such integration allows the application developer to off-load those access control functions and focus on core application features and functionality.'
  desc 'check', 'If the Mainframe Product employs an external security manager for all account management functions, this is not applicable.

Examine account management settings.

If the Mainframe Product does not automatically audit account removal actions, this is a finding.'
  desc 'fix', 'Configure the Mainframe Product account management settings to automatically audit account removal actions.'
  impact 0.5
  ref 'DPMS Target Mainframe Product'
  tag check_id: 'C-5716r299583_chk'
  tag severity: 'medium'
  tag gid: 'V-205450'
  tag rid: 'SV-205450r395493_rule'
  tag stig_id: 'SRG-APP-000029-MFP-000042'
  tag gtitle: 'SRG-APP-000029'
  tag fix_id: 'F-5716r299584_fix'
  tag 'documentable'
  tag legacy: ['SV-82633', 'V-68143']
  tag cci: ['CCI-001405']
  tag nist: ['AC-2 (4)']
end
