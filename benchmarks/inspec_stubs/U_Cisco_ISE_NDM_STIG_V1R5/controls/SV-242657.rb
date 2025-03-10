control 'SV-242657' do
  title 'The Cisco ISE must terminate all network connections associated with a device management session at the end of the session, or the session must be terminated after five minutes of inactivity except to fulfill documented and validated mission requirements.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended.'
  desc 'check', 'From the CLI EXEC mode type show terminal.
 
From the GUI navigate to Administration >> System >> Admin Access >> Settings >> Session.

View the session timeout setting.

If the terminal and administration setting is not set to five minutes or less, this is a finding.'
  desc 'fix', 'Configure Session Timeout for Administrators.

1. Choose Administration >> System >> Admin Access >> Settings >> Session >> Session Timeout.
2. Type "5".
3. Click "Save".'
  impact 0.7
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45932r916305_chk'
  tag severity: 'high'
  tag gid: 'V-242657'
  tag rid: 'SV-242657r916306_rule'
  tag stig_id: 'CSCO-NM-000520'
  tag gtitle: 'SRG-APP-000190-NDM-000267'
  tag fix_id: 'F-45889r916083_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
