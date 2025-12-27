control 'SV-85989' do
  title 'The CA API Gateway must terminate all network connections associated with a Policy Manager session at the end of the session or as follows: for in-band management sessions (privileged sessions), the session must be terminated after 10 minutes of inactivity within the Policy Manager, and for user sessions simply viewing the contents of Policy Manager or viewing Audit Logs for tracking purposes (non-privileged session), the session must be terminated after 15 minutes of inactivity.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element.

Terminating network connections associated with Policy Manager sessions includes, for example, de-allocating associated TCP/IP address/port pairs at the operating system level and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection.

The CA API Gateway must be configured to terminate any management session after an inactivity time via the Policy Manager. The default value for the Policy Manager is 30 minutes and must be configured for 10 minutes for administration sessions and 15 minutes for all other sessions, such as users viewing logs.'
  desc 'check', 'Open the CA API Gateway - Policy Manager and select "Preferences" from the main menu. 

Verify the inactivity timeout is set in accordance with organizational requirements. 

If it is not, this is a finding.'
  desc 'fix', 'Open the CA API Gateway - Policy Manager and select "Preferences" from the main menu. 

Update the inactivity timeout in accordance with organizational requirements.'
  impact 0.5
  ref 'DPMS Target CA API Gateway ALG'
  tag check_id: 'C-71765r1_chk'
  tag severity: 'medium'
  tag gid: 'V-71365'
  tag rid: 'SV-85989r1_rule'
  tag stig_id: 'CAGW-GW-000380'
  tag gtitle: 'SRG-NET-000213-ALG-000107'
  tag fix_id: 'F-77675r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
end
