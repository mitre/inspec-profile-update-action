control 'SV-88873' do
  title 'The process by which the Solidcore client Command Line Interface (CLI) Access Password is made available to administrators when needed must be documented in the organizations written policy.'
  desc 'The Solidcore client can be configured locally at the CLI, but only when accessed with the required password.

Since the McAfee Application Control configuration is to be managed by ePO policies, allowing enablement of the CLI to would introduce the capability of local configuration changes. 

Strict management of the accessibility of the CLI is necessary in order to prevent its misuse.

The misuse of the CLI would open the system up to the possible configuration changes potentially allowing malicious applications to execute unknowingly.'
  desc 'check', "Note: The CLI Access is in lockdown mode by default when being managed by ePO. Since the CLI Access can be recovered for troubleshooting, this requirement needs to be met.

Consult with the ISSO/ISSM to obtain a copy of the organization's documented policy for application whitelisting.

The policy must contain procedures for accessing the CLI password, to include the SA gaining access to an approved safe in order for obtaining the password.

If a procedure does not exist for accessing the CLI password as described above, this is a finding."
  desc 'fix', 'Follow the formal change and acceptance process to update the written policy to include procedures for accessing the CLI password and how the SA gains access to an approved safe in order for obtaining the password.'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 7.0 Managed Desktop'
  tag check_id: 'C-74235r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74199'
  tag rid: 'SV-88873r1_rule'
  tag stig_id: 'MCAC-PO-000105'
  tag gtitle: 'SRG-APP-000397'
  tag fix_id: 'F-80741r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002041']
  tag nist: ['IA-5 (1) (f)']
end
