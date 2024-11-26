control 'SV-101193' do
  title 'The Juniper router must be configured to limit the number of concurrent management sessions to an organization-defined number.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Note: This requirement is not applicable to file transfer actions such as SCP and SFTP.

Review the router configuration to determine if concurrent SSH sessions are limited as show in the example below:

system {
    services {
        ssh {
            max-sessions-per-connection 1;
            connection-limit 2;
        }
    }

Note: the max-sessions-per-connection must be set to 1 to limit the number of sessions per connection which is limited by the connection-limit.

If the router is not configured to limit the number of concurrent sessions, this is a finding.'
  desc 'fix', 'Configure the router to limit the number of concurrent sessions as shown in the example below:

[edit system services]
set ssh connection-limit 2
set ssh max-sessions-per-connection 1'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90247r2_chk'
  tag severity: 'medium'
  tag gid: 'V-91093'
  tag rid: 'SV-101193r1_rule'
  tag stig_id: 'JUNI-ND-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-97291r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
