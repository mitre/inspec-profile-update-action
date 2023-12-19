control 'SV-213317' do
  title 'The use of a Solidcore 8.x local Command Line Interface (CLI) Access Password must be documented in the organizations written policy.'
  desc 'The Solidcore client can be configured locally at the CLI, but only when accessed with the required password.

Since the McAfee Application Control configuration is to be managed by ePO policies, allowing enablement of the CLI to would introduce the capability of local configuration changes. 

Strict management of the accessibility of the CLI is necessary in order to prevent its misuse.

The misuse of the CLI would open the system up to the possible configuration changes potentially allowing malicious applications to execute unknowingly.'
  desc 'check', "Note: The CLI Access is in lockdown mode by default when being managed by ePO. Since the CLI Access can be recovered for troubleshooting, this requirement needs to be met.

Consult with the ISSO/ISSM to obtain a copy of the organization's documented policy for application whitelisting.

Review the written policy for how and when the Solidcore CLI is used by the organization.

If the use of the CLI is not documented in the organization's written policy, this is a finding."
  desc 'fix', "Follow the formal change and acceptance process to update the organization's written policy with the use of the CLI."
  impact 0.5
  ref 'DPMS Target McAfee Application Control 8.x'
  tag check_id: 'C-14545r505016_chk'
  tag severity: 'medium'
  tag gid: 'V-213317'
  tag rid: 'SV-213317r506897_rule'
  tag stig_id: 'MCAC-PO-000101'
  tag gtitle: 'SRG-APP-000165'
  tag fix_id: 'F-14543r505017_fix'
  tag 'documentable'
  tag legacy: ['SV-88893', 'V-74219']
  tag cci: ['CCI-000200']
  tag nist: ['IA-5 (1) (e)']
end
