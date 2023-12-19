control 'SV-88869' do
  title 'The Solidcore client Command Line Interface (CLI) Access Password protection process must be documented in the organizations written policy.'
  desc 'The Solidcore client can be configured locally at the CLI, but only when accessed with the required password.

Since the McAfee Application Control configuration is to be managed by ePO policies, allowing enablement of the CLI to would introduce the capability of local configuration changes. 

Strict management of the accessibility of the CLI is necessary in order to prevent its misuse.

The misuse of the CLI would open the system up to the possible configuration changes potentially allowing malicious applications to execute unknowingly.'
  desc 'check', %q(Note: The CLI Access is in lockdown mode by default when being managed by ePO. Since the CLI Access can be recovered for troubleshooting, this requirement needs to be met.

Consult with the ISSO/ISSM to obtain a copy of the organization's documented policy for application whitelisting.

Review the written policy for how the Solidcore client interface is used by the organization.

Verify the policy identifies how the CLI password is protected.

Ask the ePO admin, "What protection measures are used for the CLI password?"

The protection measures should include, at a minimum, storage in a sealed envelope, which is then stored in an approved safe.

Note: The envelope will contain the last access date along with those authorized to use it.

If the written policy does not contain specific information on how the CLI password is protected and/or if that policy does not include, at a minimum, that the password be stored in a sealed envelope in an approved safe with the last access date noted, this is a finding.)
  desc 'fix', 'Follow the formal change and acceptance process to update the written policy with specific information on how the CLI password is protected and that the password must be stored in a sealed envelope in an approved safe with the last access date noted.'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 7.0 Managed Desktop'
  tag check_id: 'C-74231r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74195'
  tag rid: 'SV-88869r1_rule'
  tag stig_id: 'MCAC-PO-000103'
  tag gtitle: 'SRG-APP-000172'
  tag fix_id: 'F-80737r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000197']
  tag nist: ['IA-5 (1) (c)']
end
