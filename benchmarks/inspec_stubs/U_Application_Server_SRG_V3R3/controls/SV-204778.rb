control 'SV-204778' do
  title 'The application server management interface must provide a logout capability for user-initiated communication session.'
  desc 'If a user cannot explicitly end an application server management interface session, the session may remain open and be exploited by an attacker; this is referred to as a zombie session.

The attacker will then have access to the application server management functions without going through the user authentication process.

To prevent this type of attack, the application server management interface must close user sessions when defined events are met and provide a logout function for users to explicitly close the session and free resources that were in use by the user.'
  desc 'check', 'Review application server documentation and configuration settings to determine if the application server management interface provides a logout capability.

If the application server management interface does not provide a logout capability, this is a finding.'
  desc 'fix', 'Configure the application server management interface to provide a logout capability for the users.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4898r282981_chk'
  tag severity: 'medium'
  tag gid: 'V-204778'
  tag rid: 'SV-204778r850834_rule'
  tag stig_id: 'SRG-APP-000296-AS-000201'
  tag gtitle: 'SRG-APP-000296'
  tag fix_id: 'F-4898r282982_fix'
  tag 'documentable'
  tag legacy: ['V-57403', 'SV-71675']
  tag cci: ['CCI-002363']
  tag nist: ['AC-12 (1)']
end
