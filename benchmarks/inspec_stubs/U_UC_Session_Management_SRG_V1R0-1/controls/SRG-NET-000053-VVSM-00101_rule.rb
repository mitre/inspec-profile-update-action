control 'SRG-NET-000053-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must limit the number of concurrent management sessions to three sessions.'
  desc 'Network element management includes the ability to control the number of users and user sessions that use a network element. Limiting the number of allowed users and sessions per user is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system.

This applies to network elements that have the concept of a user account and have the login function residing on the network element.'
  desc 'check', 'Verify the Unified Communications Session Manager limits the number of concurrent management sessions.

If the Unified Communications Session Manager does not limit the number of concurrent management sessions, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to limit the number of concurrent management sessions.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000053-VVSM-00101_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000053-VVSM-00101'
  tag rid: 'SRG-NET-000053-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000053-VVSM-00101'
  tag gtitle: 'SRG-NET-000053-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000053-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
