control 'SV-250986' do
  title 'MobileIron Sentry must be configured to enforce the limit of three consecutive invalid logon attempts, after which time it must block any login attempt for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.'
  desc 'check', 'Review MobileIron Sentry configuration to verify that it enforces the limit of three consecutive invalid logon attempts. 

1. Log in to MobileIron Sentry System Manager portal.
2. Go to the "Security" tab. 
3. Go to "Password Policy". 
4. Look for "Number of Failed Attempts" and determine if the value is set to 3. If it is not, this is a finding.
5. Verify the Auto-Lock Time value is set to 900 seconds or more. 

If the Auto-Lock Time is not set to 900 seconds or more, this is a finding.'
  desc 'fix', 'Configure MobileIron Sentry to enforce the limit of three consecutive invalid login attempts during a 15-minute time period.

1. Log in to MobileIron Sentry System Manager portal.
2. Go to the "Security" tab.
3. Go to "Password Policy".
4. For "Number of Failed Attempts", set value to 3.
5. For "Auto-Lock Time", set value to 900 seconds or more.'
  impact 0.3
  ref 'DPMS Target Ivanti MobileIron Sentry 9.x NDM'
  tag check_id: 'C-54421r802178_chk'
  tag severity: 'low'
  tag gid: 'V-250986'
  tag rid: 'SV-250986r802180_rule'
  tag stig_id: 'MOIS-ND-000140'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-54375r802179_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
