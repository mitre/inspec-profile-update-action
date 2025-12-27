control 'SV-233339' do
  title 'Forescout must use a bidirectional authentication mechanism configured with a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to authenticate with the endpoint device. This is required for compliance with C2C Step 1.'
  desc 'Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk. Currently, DoD requires the use of AES for bidirectional authentication since it is the only FIPS-validated AES cipher block algorithm.

Because of the challenges of applying this requirement on a large scale, organizations are encouraged to apply the requirement only to those limited number (and type) of devices that truly need to support this capability.'
  desc 'check', 'If DoD is not at C2C Step 1 or higher, this is not a finding.

Use the Forescout CLI credentials to verify FIPS mode is set by running the "fstool version" command and look for the "FIPS enabled" setting.

Log on using the CLIAdmin credentials established upon initial configuration.

Verify FIPS mode by typing the command "fstool version".

If Forescout does not use AES, this is a finding.'
  desc 'fix', 'To enable FIPS mode, log in to the CLI account a use the "fstool fips" command.

Note that use of FIPS mode is not mandatory in DoD. However, it is the primary method for mitigation of this requirement and ensuring FIPS compliance.

Log on using the CLIAdmin credentials established upon initial configuration.

To enable FIPS mode, type "fstool fips". A prompt alerting the user that FIPS 140-2 will be enabled will be displayed. Type "Yes" for FIPS to accept this prompt.

Note: Use of FIPS mode is not mandatory in DoD. However, it is the primary method for mitigation of this requirement and ensuring FIPS compliance.'
  impact 0.5
  ref 'DPMS Target Forescout Network Access Control'
  tag check_id: 'C-36534r811428_chk'
  tag severity: 'medium'
  tag gid: 'V-233339'
  tag rid: 'SV-233339r811429_rule'
  tag stig_id: 'FORE-NC-000460'
  tag gtitle: 'SRG-NET-000151-NAC-000630'
  tag fix_id: 'F-36499r803492_fix'
  tag 'documentable'
  tag cci: ['CCI-001967']
  tag nist: ['IA-3 (1)']
end
