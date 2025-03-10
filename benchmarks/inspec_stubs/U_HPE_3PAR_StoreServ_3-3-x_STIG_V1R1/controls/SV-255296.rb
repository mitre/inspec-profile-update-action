control 'SV-255296' do
  title 'The HPE 3PAR OS WSAPI process must be properly configured to operate in FIPS mode in order to use mechanisms meeting the requirements of applicable federal laws, executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DOD data may be compromised.

The HPE 3PAR OS cimserver utilizes a vendor-affirmed FIPS module and operates OpenSSL in FIPS mode when configured as described. If the service is not enabled in FIPS mode it is incorrectly configured.'
  desc 'check', 'If the mission does not require WSAPI functionality, this requirement is not applicable.

Verify if WSAPI is configured to run.
Use the command:
cli% showwsapi -d

If "service State" shows "Disabled", this is not applicable.

If "HTTP State" shows "Enabled", this is a finding.

If "HTTPS State" shows "Disabled", this is a finding.

If "Policy" contains "no_tls_strict", this is a finding.'
  desc 'fix', 'Stop the WSAPI process:
cli% stopwsapi -f

Reconfigure the WSAPI to use only HTTPS on TLSV1.2:
cli% setwsapi -f -http disable
cli% setwsapi -f -https enable
cli% setwsapi -f -pol tls_strict

Restart the WSAPI process:
cli% startwsapi -f

Wait up to five minutes for WSAPI to start up and verify it is Enabled/Active:
cli% showwsapi

Once WSAPI is active, verify FIPS mode:
cli% controlsecurity fips status

If WSAPI is "Disabled", this is an error that requires a service escalation.'
  impact 0.7
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58969r870205_chk'
  tag severity: 'high'
  tag gid: 'V-255296'
  tag rid: 'SV-255296r870207_rule'
  tag stig_id: 'HP3P-33-121103'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-58913r870206_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
