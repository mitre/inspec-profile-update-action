control 'SV-230969' do
  title 'Forescout must use FIPS 140-2 approved algorithms for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms used for authentication to the cryptographic module are not validated and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Network devices utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. However, authentication algorithms must configure security processes to use only FIPS-approved and NIST-recommended authentication algorithms.'
  desc 'check', 'Log on using the CLIAdmin credentials established upon initial configuration.

Verify FIPS mode by typing the command "fstool version".

If Forescout does not use FIPS 140-2 approved algorithms for authentication to a cryptographic module, this is a finding.'
  desc 'fix', 'To enable FIPS mode on the Forescout appliance, start by opening a secure shell to the CLI of the management appliance using Putty or another tool.

Log on using the CLIAdmin credentials established upon initial configuration.

To enable FIPS mode, type "fstool fips". At the prompt to alert the user FIPS 140-2 will be enabled, type "Yes" to accept.

Note: Use of FIPS mode is not mandatory in DoD. However, it is the primary method for mitigation of this requirement and ensuring FIPS compliance.'
  impact 0.7
  ref 'DPMS Target Forescout Network Device Management'
  tag check_id: 'C-33899r603746_chk'
  tag severity: 'high'
  tag gid: 'V-230969'
  tag rid: 'SV-230969r615886_rule'
  tag stig_id: 'FORE-NM-000430'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-33872r615884_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
