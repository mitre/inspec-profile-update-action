control 'SV-252201' do
  title 'The HPE Nimble must limit the number of concurrent sessions to an organization-defined number for each administrator account.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.

The product contains the ability to limit the number of total sessions, but not by individual user or user type.'
  desc 'check', 'Verify that in Administration >> Security Policies page in the UI, "Unlimited" for the number of sessions is unchecked and a limit is specified.

If a limit is not specified, this is a finding.'
  desc 'fix', 'On the Administration >> Security Policies page in the UI, uncheck "Unlimited" for the number of sessions and specify a new limit.'
  impact 0.5
  ref 'DPMS Target HPE Nimble Storage Array'
  tag check_id: 'C-55657r814081_chk'
  tag severity: 'medium'
  tag gid: 'V-252201'
  tag rid: 'SV-252201r814083_rule'
  tag stig_id: 'HPEN-NM-000160'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-55607r814082_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
