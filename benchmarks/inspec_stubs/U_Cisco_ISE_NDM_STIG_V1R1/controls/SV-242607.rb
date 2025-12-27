control 'SV-242607' do
  title 'For the account of last resort, the Cisco ISE must limit the number of concurrent sessions to one.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Review the local account of last resort limit for maximum number of concurrent users based to verify the setting is set based on user or identity group.

1. Choose Administration >> System >> Settings >> Max Sessions >> User.
2. Choose Administration >> System >> Settings >> Max Sessions >> Group.

MaxSessionsPerUser: 1

If the local account is not set to limit the maximum number of sessions to "1", this is a finding.'
  desc 'fix', 'Configure local account maximum concurrent sessions based. There must be only one local account of last resort on each node.

1. Choose Administration >> System >> Settings >> Max Sessions >> User.
2. Set the Maximum Sessions per User field to "1".
3. Click "Save".'
  impact 0.3
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45882r714129_chk'
  tag severity: 'low'
  tag gid: 'V-242607'
  tag rid: 'SV-242607r714131_rule'
  tag stig_id: 'CSCO-NM-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-45839r714130_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
