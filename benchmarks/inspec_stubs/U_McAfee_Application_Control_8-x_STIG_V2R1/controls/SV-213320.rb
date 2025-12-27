control 'SV-213320' do
  title 'The requirement for scheduled Solidcore client Command Line Interface (CLI) Access Password changes must be documented in the organizations written policy.'
  desc 'The Solidcore client can be configured locally at the CLI, but only when accessed with the required password.

The misuse of the CLI would open the system up to the possible configuration, allowing malicious applications to execute unknowingly. Strict management of the accessibility of the CLI is necessary in order to prevent its misuse.'
  desc 'check', "Note: The CLI Access is in lockdown mode by default when being managed by ePO. Since the CLI Access can be recovered for troubleshooting, this requirement needs to be met.

Consult with the ISSO/ISSM to obtain a copy of the organization's documented policy for application whitelisting.

Review the written policy for how the Solidcore client interface is used by the organization.

Verify the policy identifies the frequency with which the CLI password is changed.

If the written policy does not contain specific information on frequency with which the CLI password is changed, this is a finding."
  desc 'fix', 'Follow the formal change and acceptance process to update the written policy with specific information on the frequency with which the CLI password is changed.'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14548r309057_chk'
  tag severity: 'medium'
  tag gid: 'V-213320'
  tag rid: 'SV-213320r506897_rule'
  tag stig_id: 'MCAC-PO-000104'
  tag gtitle: 'SRG-APP-000174'
  tag fix_id: 'F-14546r309058_fix'
  tag 'documentable'
  tag legacy: ['SV-88871', 'V-74197']
  tag cci: ['CCI-000199']
  tag nist: ['IA-5 (1) (d)']
end
