control 'SV-256071' do
  title 'The Riverbed NetProfiler must be configured to limit the number of concurrent sessions to one for the locally defined administrator account.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to denial-of-service (DOS) attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Go to Administration >> Account Management >> User Accounts. 

Click "Settings". 

Check under "Log-in Settings".

If the "Allow only one log-in per user name/password combination" box is not checked, this is a finding.'
  desc 'fix', 'Go to Administration >> Account Management >> User Accounts. 

Click "Settings". 

Under "Log-in Settings", check the "Allow only one log-in per user name/password combination" box. 

Click "OK" to save the settings.'
  impact 0.3
  ref 'DPMS Target Riverbed NetProfiler'
  tag check_id: 'C-59745r882719_chk'
  tag severity: 'low'
  tag gid: 'V-256071'
  tag rid: 'SV-256071r882721_rule'
  tag stig_id: 'RINP-DM-000001'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-59688r882720_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
