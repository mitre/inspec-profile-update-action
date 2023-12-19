control 'SV-90955' do
  title 'CounterACT must limit the number of concurrent sessions to an organization-defined number for each administrator account type.'
  desc 'Network device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.'
  desc 'check', 'Determine if CounterACT requires a limit of one session per user. This requirement may be verified by demonstration or configuration review.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Verify the "allow only one login session per user" radio button is selected and configured to either Log out existing session or Deny new logon attempts.

If CounterACT does not enforce one session per user, this is a finding.'
  desc 'fix', 'Configure CounterACT to require a limit of one session per user.

1. Log on to the CounterACT Administrator UI.
2. From the menu, select Tools >> Options >> User Console and Options >> Password and Login.
3. Ensure the "allow only one login session per user" radio button is selected and configured to either Log out existing session or Deny new logon attempts.'
  impact 0.3
  ref 'DPMS Target ForeScout CounterACT NDM'
  tag check_id: 'C-75953r1_chk'
  tag severity: 'low'
  tag gid: 'V-76267'
  tag rid: 'SV-90955r1_rule'
  tag stig_id: 'CACT-NM-000051'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-82903r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
