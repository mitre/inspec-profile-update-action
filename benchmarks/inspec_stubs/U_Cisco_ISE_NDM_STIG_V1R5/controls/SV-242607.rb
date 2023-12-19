control 'SV-242607' do
  title 'The Cisco ISE must limit the number of CLI sessions to one and organization-defined number for the GUI.'
  desc 'Device management includes the ability to control the number of management sessions that manage a device. Limiting the number of allowed sessions is helpful in limiting risks related to DoS attacks.

This requirement addresses concurrent sessions for administrative access. The maximum number of concurrent sessions should be defined based upon mission needs and the operational environment for each system. At a minimum, limits must be set for SSH and HTTPS sessions.'
  desc 'check', 'Review the concurrent sessions to ensure the CLI and GUI have the correct number of sessions defined. 

From web Admin portal:
1. Choose Administration >> System >>Admin Access >> Settings >> Access.
2. Verify the "Maximum Concurrent Sessions" under "GUI" Sessions is set to the organization-defined number.
3. Verify the "Maximum Concurrent Sessions" under "CLI" Sessions is set to one.

If the CLI is not set to limit the maximum number of sessions to one or the GUI is not set to limit the maximum number of sessions to the organization-defined number, then this is a finding.'
  desc 'fix', 'Configure the concurrent sessions for the CLI and GUI. 

From web admin portal:
1. Choose Administration >> System >>Admin Access >> Settings >> Access.
2. Configure the "Maximum Concurrent Sessions" under "GUI" to be the organization-defined number.
3. Configure the "Maximum Concurrent Sessions" under "CLI" to be one.'
  impact 0.3
  ref 'DPMS Target Cisco ISE NDM'
  tag check_id: 'C-45882r822783_chk'
  tag severity: 'low'
  tag gid: 'V-242607'
  tag rid: 'SV-242607r879511_rule'
  tag stig_id: 'CSCO-NM-000010'
  tag gtitle: 'SRG-APP-000001-NDM-000200'
  tag fix_id: 'F-45839r822786_fix'
  tag 'documentable'
  tag cci: ['CCI-000054']
  tag nist: ['AC-10']
end
