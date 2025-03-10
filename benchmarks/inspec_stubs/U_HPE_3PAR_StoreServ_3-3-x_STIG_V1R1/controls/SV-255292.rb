control 'SV-255292' do
  title 'The HPE 3PAR OS cimserver process must be properly configured to operate in FIPS mode in order to use mechanisms meeting the requirements of applicable federal laws, executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DOD data may be compromised.

The HPE 3PAR OS cimserver utilizes a vendor-affirmed FIPS module and operates OpenSSL in FIPS mode when configured as described. If the service is not enabled in FIPS mode, it is incorrectly configured.'
  desc 'check', 'If the mission does not require CIM functionality, this requirement is not applicable.

Verify cim is configured:
cli% showcim

If there is an error, this is a finding.

If the output indicates the service is "Disabled", the state is "Inactive", HTTP is "Enabled", or HTTPS is "Disabled", this is a finding.

Check the FIPS status
cli% controlsecurity fips status

If there is an error, or CIM shows as "Disabled", this is a finding.'
  desc 'fix', 'Stop the cimserver process:
cli% stopcim -f

Reconfigure the cimserver to use only HTTPS on TLSV1.2
cli% setcim -f -http disable
cli% setcim -f -https enable
cli% setcim -f -pol tls_strict

Restart the cimserver process:
cli% startcim -f

Wait up to five minutes for CIM to start up and verify it is Enabled/Active 
cli% showcim

Once CIM is active, verify FIPS mode:
cli% controlsecurity fips status

If CIM is "Disabled", this is an error that requires a service escalation.'
  impact 0.7
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58965r870193_chk'
  tag severity: 'high'
  tag gid: 'V-255292'
  tag rid: 'SV-255292r870195_rule'
  tag stig_id: 'HP3P-33-111103'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-58909r870194_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
