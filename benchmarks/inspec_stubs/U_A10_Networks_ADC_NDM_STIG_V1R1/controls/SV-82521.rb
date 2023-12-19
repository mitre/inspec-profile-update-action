control 'SV-82521' do
  title 'The A10 Networks ADC must limit the number of concurrent sessions to one (1) for each administrator account and/or administrator account type.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Review the device configuration.

The following command shows the configuration with an output modifier to display only the phrase "multiple-auth-reject":
show run | inc  multiple-auth-reject

If the output is blank, this is a finding.'
  desc 'fix', 'The following command disables concurrent logons for any administrative account:
authentication multiple-auth-reject'
  impact 0.5
  ref 'DPMS Target A10 Networks ADC NDM'
  tag check_id: 'C-68591r1_chk'
  tag severity: 'medium'
  tag gid: 'V-68031'
  tag rid: 'SV-82521r1_rule'
  tag stig_id: 'AADC-NM-000001'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-74147r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
