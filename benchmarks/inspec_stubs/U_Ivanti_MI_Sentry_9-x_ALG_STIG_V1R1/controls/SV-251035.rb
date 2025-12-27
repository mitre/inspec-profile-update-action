control 'SV-251035' do
  title 'The Sentry must reveal error messages only to the ISSO, ISSM, and SCA.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can give configuration details about the network element. 

Limiting access to system logs and administrative consoles to authorized personnel will help to mitigate this risk. However, user feedback and error messages should also be restricted by type and content in accordance with security best practices (e.g., ICMP messages)."
  desc 'check', 'Verify the Sentry reveals error messages only to the ISSO, ISSM, and SCA. 

1. Log in to MobileIron Sentry.
2. Go to Monitoring >> Alert Configuration.
3. Verify "Send Notifications" is enabled.
4. Verify an email list containing the ISSO, ISSM, and SCA is input in the Email List.
5. Verify the "Alert Notification Management" section is set to meet organizational requirements.

If Sentry is not configured to reveal error messages only to the ISSO, ISSM, and SCA, this is a finding.'
  desc 'fix', 'Configure the Sentry to reveal error messages only to the ISSO, ISSM, and SCA.

1. Log in to MobileIron Sentry.
2. Go to Monitoring >> Alert Configuration.
3. Enable "Send Notifications".
4. Configure an email list containing the ISSO, ISSM, and SCA in the Email List.
5. Configure the "Alert Notification Management" section to meet organizational requirements.'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x ALG'
  tag check_id: 'C-54470r802325_chk'
  tag severity: 'low'
  tag gid: 'V-251035'
  tag rid: 'SV-251035r802327_rule'
  tag stig_id: 'MOIS-AL-001200'
  tag gtitle: 'SRG-NET-000402-ALG-000130'
  tag fix_id: 'F-54424r802326_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
