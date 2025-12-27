control 'SV-251400' do
  title 'The Ivanti MobileIron Core server must limit the number of concurrent sessions per privileged user account to three or less concurrent sessions.'
  desc 'Application management includes the ability to control the number of users and user sessions that utilize an application. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement may be met via the application or by utilizing information system session control provided by a web server with specialized session management capabilities. If it has been specified that this requirement will be handled by the application, the capability to limit the maximum number of concurrent single user sessions must be designed and built into the application. 

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions must be defined based upon mission needs and the operational environment for each system. 

'
  desc 'check', 'Perform the following procedure to limit concurrent sessions per privileged users:

On the Admin page for each privileged user, verify Actions Edit Role select "Enforce single session (all spaces)" is selected.

If "Enforce single session (all spaces)" is not selected for each user, this is a finding.'
  desc 'fix', 'Use the following procedure to limit the number of concurrent sessions:

In the Admin Portal, go to "Admin" Actions edit Roles "Enforce single session (all spaces)".'
  impact 0.5
  ref 'DPMS Target Ivanti MobileIron Core MDM Server'
  tag check_id: 'C-54835r806330_chk'
  tag severity: 'medium'
  tag gid: 'V-251400'
  tag rid: 'SV-251400r806332_rule'
  tag stig_id: 'IMIC-11-000100'
  tag gtitle: 'SRG-APP-000001-UEM-000001'
  tag fix_id: 'F-54788r806331_fix'
  tag satisfies: ['FMT_SMF.1.1(2) b \nReference: PP-MDM-431010']
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
