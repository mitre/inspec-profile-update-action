control 'SV-88895' do
  title 'The Solidcore client Command Line Interface (CLI) Access password complexity requirements must be documented in the organizations written policy.'
  desc 'The Solidcore client can be configured locally at the CLI, but only when accessed with the required password.

The misuse of the CLI would open the system up to the possible configuration, allowing malicious applications to execute unknowingly. Strict management of the accessibility of the CLI is necessary in order to prevent its misuse.'
  desc 'check', "Note: The CLI Access is in lockdown mode by default when being managed by ePO. Since the CLI Access can be recovered for troubleshooting, this requirement needs to be met.

Since the Solidcore CLI does not allow for technical enforcement of password complexity the enforcement will be via this written policy directive.

Consult with the ISSO/ISSM to obtain a copy of the organization's documented policy for application whitelisting.

Review the written policy for CLI password complexity requirements.

Verify the policy requires the password to be 15 characters in length and contain a mix of at least one lower-case, one upper-case, one number, and one special character.

If the written policy does not document the requirement for password complexity and/or does not specify the password must be 15 characters in length and contain a mix of at least one lower-case, one upper-case, one number, and one special character, this is a finding."
  desc 'fix', 'Follow the formal change and acceptance process to update the written policy with the CLI password complexity requirements.'
  impact 0.5
  ref 'DPMS Target McAfee Application Control 7.0 Managed Desktop'
  tag check_id: 'C-74257r1_chk'
  tag severity: 'medium'
  tag gid: 'V-74221'
  tag rid: 'SV-88895r1_rule'
  tag stig_id: 'MCAC-PO-000102'
  tag gtitle: 'SRG-APP-000169'
  tag fix_id: 'F-80763r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001619']
  tag nist: ['IA-5 (1) (a)']
end
