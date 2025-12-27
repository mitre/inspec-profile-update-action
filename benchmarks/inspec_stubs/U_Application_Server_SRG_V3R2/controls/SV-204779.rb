control 'SV-204779' do
  title 'The application server management interface must display an explicit logout message to users indicating the reliable termination of authenticated communications sessions.'
  desc 'Providing a logout capability to the user allows the user to explicitly close a session and free those resources used during the session.

If a user cannot explicitly end an application session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.

The attacker will then have access to the application server management functions without going through the user authentication process.

To inform the user that the session has been reliably closed, a logout message must be displayed to the user.'
  desc 'check', 'Review application server documentation and configuration settings to determine if the application server management interface displays a logout message.

If the application server management interface does not display a logout message, this is a finding.'
  desc 'fix', 'Configure the application server management interface to display an explicit logout message to users.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4899r282984_chk'
  tag severity: 'medium'
  tag gid: 'V-204779'
  tag rid: 'SV-204779r508029_rule'
  tag stig_id: 'SRG-APP-000297-AS-000188'
  tag gtitle: 'SRG-APP-000297'
  tag fix_id: 'F-4899r282985_fix'
  tag 'documentable'
  tag legacy: ['V-57405', 'SV-71677']
  tag cci: ['CCI-002364']
  tag nist: ['AC-12 (2)']
end
