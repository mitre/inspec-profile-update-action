control 'SV-251006' do
  title 'MobileIron Sentry must be configured to send log data to a central log server for the purpose of forwarding alerts to the administrators and the ISSO.'
  desc 'Without syslog enabled it will be difficult for an ISSO to correlate the users behavior and identify potential threats within the logs.'
  desc 'check', 'To identify/validate MobileIron Sentry support for syslog forwarding, follow the navigation steps below. 

1. Log in to the MobileIron Sentry.
2. Navigate to "Settings".
3. Scroll down to "Syslog".
4. Verify that a syslog server has been configured correctly. 
      a. Verify Server IP address.
      b. Verify Port.
      c. Verify Facility Types.
      d. Verify Admin state is enabled.

If syslog forwarding has not been implemented, this is a finding.'
  desc 'fix', 'Configure the MobileIron Sentry to forward syslog data using the steps below Refer to "MobileIron Sentry Guide for Core", section "Syslog", page 140.
  
 1. Log in to the MobileIron Sentry.
 2. Navigate to "Settings".
 3. Scroll down to "Syslog".
 4. If there is no syslog server entry, ADD the server:
      a. Add Server IP address.
      b. Add Port.
      c. Select/add Facility Types and Log Levels.
     d. Enable Admin state.'
  impact 0.7
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54441r802238_chk'
  tag severity: 'high'
  tag gid: 'V-251006'
  tag rid: 'SV-251006r802240_rule'
  tag stig_id: 'MOIS-ND-000980'
  tag gtitle: 'SRG-APP-000516-NDM-000350'
  tag fix_id: 'F-54395r802239_fix'
  tag 'documentable'
  tag cci: ['CCI-002605']
  tag nist: ['SI-2 c']
end
