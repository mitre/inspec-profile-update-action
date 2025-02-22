control 'SV-253885' do
  title 'The Juniper EX switch must be configured to enforce the limit of three consecutive invalid logon attempts for any given user, after which time it must block any login attempt for that user for 15 minutes.'
  desc 'By limiting the number of failed login attempts, the risk of unauthorized system access via user password guessing, otherwise known as brute-forcing, is reduced. Introducing a lockout period significantly increases the time required for each brute-force attack and increases the likelihood that security personnel will identify (and can respond to) an ongoing attack and/or that the authorized owner will recognize and report the unauthorized activity.'
  desc 'check', 'Juniper switches maintain the number of failed login attempts per user until the session is restarted or, if lockout-period is configured, until the next successful login. If the permissible number of failed login attempts is reached, the switch prevents logging in for the duration of the lockout-period (1..43200 minutes) regardless whether the account is locally or externally authenticated and across all management access methods (e.g., local console and SSH).

Review the device configuration to verify that it enforces the limit of three consecutive invalid logon attempts before introducing a 15 minute lockout period.

[edit system login]
retry-options {
    tries-before-disconnect 3;
    lockout-period 15;
}

If the device is not configured to enforce the limit of three consecutive invalid logon attempts before introducing a 15-minute block on subsequent login attempts, this is a finding.'
  desc 'fix', 'Configure the network device to enforce the limit of three consecutive invalid logon attempts and to block subsequent login attempts for 15 minutes.

set system login retry-options tries-before-disconnect 3
set system login retry-options lockout-period 15'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches NDM'
  tag check_id: 'C-57337r844934_chk'
  tag severity: 'medium'
  tag gid: 'V-253885'
  tag rid: 'SV-253885r879546_rule'
  tag stig_id: 'JUEX-NM-000080'
  tag gtitle: 'SRG-APP-000065-NDM-000214'
  tag fix_id: 'F-57288r843687_fix'
  tag 'documentable'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
end
