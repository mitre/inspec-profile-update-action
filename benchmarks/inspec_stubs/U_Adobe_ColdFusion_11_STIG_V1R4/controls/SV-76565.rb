control 'SV-76565' do
  title 'ColdFusion must limit concurrent sessions to the Administrator Console.'
  desc 'The ColdFusion Administrator Console is used to manage the ColdFusion application server.  The console allows a user to configure settings used by hosted applications, maintain connections to external resources, review logs, etc.  By disallowing concurrent logons, a user has a method to determine if his account has been comprised (The user will be unable to log into the Administrator Console.) and deters a user from having an open idle session from different work stations which can also be used by an attacker.'
  desc 'check', 'Within the Administrator Console, navigate to the "Administrator" settings under the "Security" menu.

If the setting "Allow concurrent login sessions for Administrator Console" is checked, this is a finding.'
  desc 'fix', 'Within the Administrator Console, navigate to the "Administrator" settings under the "Security" menu. To disable concurrent logins, uncheck the "Allow concurrent login sessions for Administrator Console" setting and select the "Submit Changes" button.'
  impact 0.3
  ref 'DPMS Target ColdFusion 11'
  tag check_id: 'C-62879r2_chk'
  tag severity: 'low'
  tag gid: 'V-62075'
  tag rid: 'SV-76565r1_rule'
  tag stig_id: 'CF11-01-000001'
  tag gtitle: 'SRG-APP-000001-AS-000001'
  tag fix_id: 'F-67995r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
