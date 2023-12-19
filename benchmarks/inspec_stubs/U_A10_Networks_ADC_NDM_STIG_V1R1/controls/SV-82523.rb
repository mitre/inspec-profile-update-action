control 'SV-82523' do
  title 'The A10 Networks ADC must enforce the limit of three consecutive invalid logon attempts.'
  desc 'By limiting the number of failed logon attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced.

The A10 Networks ADC must be configured to limit the consecutive invalid logon attempts. When someone attempts to log on, but fails repeatedly, the failed logon attempts and associated "user is disabled" message will be logged. Note: The user will still be prompted up to five times, even when the account is disabled at three failed logon attempts.'
  desc 'check', 'Review the configuration.

The following command shows the device configuration and filters the output on the keyword "lockout":
show run | inc lockout

View the output; it will contain these commands:
admin lockout enable
admin lockout reset-time 15
admin lockout threshold 3

If it does not, this is a finding.'
  desc 'fix', 'The following command enables admin lockout:
admin lockout enable

The following example locks the admin account after three failed logon attempts sets the A10 ADC to remember the last failed logon for 15 minutes:
admin lockout threshold 3
admin lockout reset-time 15
Note: This will be applied to all administrative accounts.'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68593r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68033'
  tag rid: 'SV-82523r1_rule'
  tag stig_id: 'AADC-NM-000015'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-74149r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
