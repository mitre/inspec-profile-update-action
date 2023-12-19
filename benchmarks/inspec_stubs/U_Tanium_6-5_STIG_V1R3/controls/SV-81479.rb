control 'SV-81479' do
  title 'The Tanium Client Deployment Tool (CDT) must not be configured to use the psexec method of deployment.'
  desc 'When using the Tanium Client Deployment Tool (CDT), using psexec represents an increased vulnerability as the NTLM hash and clear text passwords of the authenticating user is exposed in the memory of the remote system.

To mitigate this vulnerability, the psexec method of deployment must not be used.'
  desc 'check', 'NOTE: The Tanium Server uses a renamed version of the psexec tool to be used when deploying packages to clients. In order to ensure psexec is not used, the renamed psexect.exe must be removed from the Tanium Server directory.

Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Navigate to \\Program Files(x86)\\Tanium\\Tanium Client Deployment Tool folder.

If the file "psexect.exe" exists, this is a finding.'
  desc 'fix', 'Access the Tanium Server interactively.

Log on with an account with administrative privileges to the server.

Navigate to \\Program Files(x86)\\Tanium\\Tanium Client Deployment Tool folder.

Remove the file "psexect.exe".'
  impact 0.5
  ref 'DPMS Target Tanium 6.5'
  tag check_id: 'C-67625r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66989'
  tag rid: 'SV-81479r1_rule'
  tag stig_id: 'TANS-CL-000010'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-73089r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
