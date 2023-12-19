control 'SV-216522' do
  title 'The Cisco router must be configured to limit the number of concurrent management sessions to an organization-defined number.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Note: This requirement is not applicable to file transfer actions such as FTP, SCP and SFTP.

Review the router configuration to determine if concurrent management sessions are limited as show in the example below:

ssh server session-limit 2

If the router is not configured to limit the number of concurrent management sessions, this is a finding.'
  desc 'fix', 'Configure the router to limit the number of concurrent management sessions to an organization-defined number as shown in the example below.

RP/0/0/CPU0:R3(config)#ssh server session-limit 2'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router NDM'
  tag check_id: 'C-17757r288252_chk'
  tag severity: 'medium'
  tag gid: 'V-216522'
  tag rid: 'SV-216522r531088_rule'
  tag stig_id: 'CISC-ND-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-17754r288253_fix'
  tag 'documentable'
  tag legacy: ['SV-105509', 'V-96371']
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
