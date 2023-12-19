control 'SV-239896' do
  title 'The Cisco ASA must be configured to limit the number of concurrent management sessions to an organization-defined number.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative accounts and does not address concurrent sessions by a single administrator via multiple administrative accounts. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH, HTTPS, account of last resort, and root account sessions.'
  desc 'check', 'Review the ASA configuration to determine if concurrent management sessions are limited as show in the example below:

quota management-session 2

Note: This requirement is not applicable to file transfer actions such as FTP, SCP, and SFTP. The default is 5 sessions, which would not be shown in the configuration unless the show run all command is used.
 
If the ASA is not configured to limit the number of concurrent management sessions, this is a finding.'
  desc 'fix', 'Configure the ASA to limit the number of concurrent management sessions to an organization-defined number as shown in the example below.

ASA(config)# quota management-session 2'
  impact 0.5
  ref 'DPMS Target Cisco ASA NDM'
  tag check_id: 'C-43129r666049_chk'
  tag severity: 'medium'
  tag gid: 'V-239896'
  tag rid: 'SV-239896r879511_rule'
  tag stig_id: 'CASA-ND-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-43088r666050_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
