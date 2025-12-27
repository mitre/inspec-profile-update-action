control 'SV-234043' do
  title 'The Tanium Client Deployment Tool (CDT) must not be configured to use the psexec method of deployment.'
  desc 'When using the Tanium Client Deployment Tool (CDT), using psexec represents an increased vulnerability as the NTLM hash and clear text passwords of the authenticating user is exposed in the memory of the remote system.

To mitigate this vulnerability, the psexec method of deployment must not be used.'
  desc 'check', 'Access the Tanium Module Server interactively.

Log on to the server with an account that has administrative privileges.

Navigate to Program Files(x86) >> Tanium >> Tanium Client Deployment Tool.

If the file "psexec.exe" exists, this is a finding.'
  desc 'fix', 'Access the Tanium Module Server interactively.

Log on to the server with an account that has administrative privileges.

Navigate to Program Files(x86) >> Tanium >> Tanium Client Deployment Tool.

Remove the file "psexec.exe".'
  impact 0.5
  ref 'DPMS Target Tanium 7.3'
  tag check_id: 'C-37228r610629_chk'
  tag severity: 'medium'
  tag gid: 'V-234043'
  tag rid: 'SV-234043r612749_rule'
  tag stig_id: 'TANS-CL-000010'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-37193r610630_fix'
  tag 'documentable'
  tag legacy: ['SV-102159', 'V-92057']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
