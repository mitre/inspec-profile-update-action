control 'SV-246819' do
  title 'The HYCU 4.1 application and server must limit the number of concurrent sessions to an organization-defined number for each administrator account and/or administrator account type.'
  desc 'Device management includes the ability to control the number of administrators and management sessions that manage a device. Limiting the number of allowed administrators and sessions per administrator based on account type, role, or access type is helpful in limiting risks related to DoS attacks.'
  desc 'check', 'In the HYCU Web UI, only one logon can be used at a time.

If the previous connection is not logged upon logging on to the Web UI again with the same credentials, this is a finding.

Log on to the HYCU VM console. To check number of allowed concurrent session connections, grep file "/etc/security/limits.conf" by executing the following command:
grep maxlogins /etc/security/limits.conf

Verify the following line exists:
hycu            hard    maxlogins       1

If the "maxlogins" value is not set to 1 or is missing, this is a finding.'
  desc 'fix', 'The Web UI will only always allow one user session at a time.

For CLI, configure the operating system to limit the max number of concurrent sessions to 1 by adding the following line to "/etc/security/limits.conf":
hycu            hard    maxlogins       1'
  impact 0.5
  ref 'DPMS Target HYCU for Nutanix'
  tag check_id: 'C-50251r768119_chk'
  tag severity: 'medium'
  tag gid: 'V-246819'
  tag rid: 'SV-246819r768121_rule'
  tag stig_id: 'HYCU-AC-000001'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-50205r768120_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
