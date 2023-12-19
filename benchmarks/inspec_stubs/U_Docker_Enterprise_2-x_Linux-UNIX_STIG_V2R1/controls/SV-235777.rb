control 'SV-235777' do
  title 'FIPS mode must be enabled on all Docker Engine - Enterprise nodes.'
  desc 'When FIPS mode is enabled on a Docker Engine - Enterprise node, it uses FIPS-validated cryptography to protect the confidentiality of remote access sessions to any bound TCP sockets with TLS enabled and configured. FIPS mode in Docker Engine - Enterprise is automatically enabled when FIPS mode is also enabled on the underlying host operating system.

This control is only configurable for the Docker Engine - Enterprise component of Docker Enterprise as only the Engine includes FIPS-validated cryptography. Neither Universal Control Plane (UCP) nor Docker Trusted Registry (DTR) include FIPS-validated cryptography at this time. However, both UCP and DTR will include FIPS-validated cryptography in a future release. Therefore, for UCP/DTR this control is applicable but not yet met.

'
  desc 'check', 'This check only applies to Docker Engine - Enterprise.

Verify FIPS mode is enabled on the host operating system.

Execute the following command to verify that FIPS mode is enabled on the Engine:

docker info

The "Security Options" section in the response should show a "fips" label, indicating that, when configured, the remotely accessible Engine API uses FIPS-validated digital signatures in conjunction with an approved hash function to protect the integrity of remote access sessions.

If the "fips" label is not shown in the "Security Options" section, then this is a finding.'
  desc 'fix', 'Enable FIPS mode on the host operating system. Start the Engine after FIPS mode is enabled on the host to automatically enable FIPS mode on the Engine.

FIPS mode can also be enabled by explicitly setting the DOCKER_FIPS=1 environment variable in an active terminal session prior to the execution of any Docker commands.'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-38996r627456_chk'
  tag severity: 'high'
  tag gid: 'V-235777'
  tag rid: 'SV-235777r627458_rule'
  tag stig_id: 'DKER-EE-001070'
  tag gtitle: 'SRG-APP-000015'
  tag fix_id: 'F-38959r627457_fix'
  tag satisfies: ['SRG-APP-000015', 'SRG-APP-000231', 'SRG-APP-000014', 'SRG-APP-000570', 'SRG-APP-000395', 'SRG-APP-000514', 'SRG-APP-000416', 'SRG-APP-000156', 'SRG-APP-000172', 'SRG-APP-000179', 'SRG-APP-000224', 'SRG-APP-000411', 'SRG-APP-000412', 'SRG-APP-000555', 'SRG-APP-000635']
  tag 'documentable'
  tag legacy: ['SV-104697', 'V-94867']
  tag cci: ['CCI-001453', 'CCI-001941', 'CCI-001967', 'CCI-001188', 'CCI-001199', 'CCI-000803', 'CCI-000068', 'CCI-000197', 'CCI-002450', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'IA-2 (8)', 'IA-3 (1)', 'SC-23 (3)', 'SC-28', 'IA-7', 'AC-17 (2)', 'IA-5 (1) (c)', 'SC-13 b', 'MA-4 (6)', 'MA-4 (6)']
end
