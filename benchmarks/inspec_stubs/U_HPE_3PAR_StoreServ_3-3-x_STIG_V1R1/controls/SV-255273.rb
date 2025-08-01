control 'SV-255273' do
  title 'The HPE 3PAR OS must be configured to initialize its FIPS module to use mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DOD data may be compromised.'
  desc 'check', 'Verify the status of FIPS operation mode:

cli% controlsecurity fips status

If the output indicates FIPS mode is disabled, this is a finding.

If the output shows CIM is disabled, and CIM is an essential service for the mission, this is a finding.

If the output shows VASA is disabled, and VASA is an essential service for the mission, this is a finding.

If the output shows WSAPI is disabled, and WSAPI is an essential service for the mission, this is a finding.

If the output shows any other service status as Disabled, this is a finding.'
  desc 'fix', 'To initialize the FIPS module use:

cli% controlsecurity fips enable

Warning: Enabling FIPS mode requires restarting all system management interfaces, which will terminate ALL existing connections including this one.
When that happens, you must reconnect to continue.
Continue enabling FIPS mode (yes/no)?
yes

After reconnecting, verify FIPS mode with:
cli% controlsecurity fips status'
  impact 0.7
  ref 'DPMS Target HPE 3PAR StoreServ 3.3.x'
  tag check_id: 'C-58946r870136_chk'
  tag severity: 'high'
  tag gid: 'V-255273'
  tag rid: 'SV-255273r870138_rule'
  tag stig_id: 'HP3P-33-001103'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-58890r870137_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
