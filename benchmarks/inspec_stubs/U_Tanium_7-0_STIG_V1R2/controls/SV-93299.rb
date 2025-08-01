control 'SV-93299' do
  title 'The Tanium Client Deployment Tool (CDT) must not be configured to use the psexec method of deployment.'
  desc 'When using the Tanium Client Deployment Tool (CDT), using psexec represents an increased vulnerability as the NTLM hash and clear text passwords of the authenticating user is exposed in the memory of the remote system.

To mitigate this vulnerability, the psexec method of deployment must not be used.'
  desc 'check', 'Access the Tanium Module Server interactively.

Log on with an account with administrative privileges to the server.

Navigate to Program Files(x86) >> Tanium >> Tanium Client Deployment Tool.

If the file "psexec.exe" exists, this is a finding.'
  desc 'fix', 'Access the Tanium Module Server interactively.

Log on with an account with administrative privileges to the server.

Navigate to Program Files(x86) >> Tanium >> Tanium Client Deployment Tool.

Remove the file "psexec.exe".'
  impact 0.5
  ref 'DPMS Target Tanium 7.0'
  tag check_id: 'C-78163r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78593'
  tag rid: 'SV-93299r1_rule'
  tag stig_id: 'TANS-CL-000010'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-85329r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
