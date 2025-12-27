control 'SV-235826' do
  title 'Docker Secrets must be used to store configuration files and small amounts of user-generated data (up to 500 kb in size) in Docker Enterprise.'
  desc "By leveraging Docker Secrets or Kubernetes secrets to store configuration files and small amounts of user-generated data (up to 500 kb in size), the data is encrypted at rest by the Engine's FIPS-validated cryptography."
  desc 'check', 'Review System Security Plan (SSP) and identify applications that leverage configuration files and/or small amounts of user-generated data, ensure that data is stored in Docker Secrets or Kubernetes Secrets.

Using a Universal Control Plane (UCP) client bundle, verify that secrets are in use by executing the following commands:

docker secret ls

Confirm containerized applications identified in SSP as utilizing Docker secrets have a corresponding secret configured.
If the SSP requires Docker secrets be used but the containerized application does not use Docker secrets, this is a finding.'
  desc 'fix', 'For all containerized applications that leverage configuration files and/or small amounts of user-generated data, store that data in Docker Secrets.

All secrets should be created and managed using a UCP client bundle.

A reference for the use of docker secrets can be found at https://docs.docker.com/engine/swarm/secrets/.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39045r627603_chk'
  tag severity: 'medium'
  tag gid: 'V-235826'
  tag rid: 'SV-235826r627605_rule'
  tag stig_id: 'DKER-EE-002660'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-39008r627604_fix'
  tag 'documentable'
  tag legacy: ['SV-104823', 'V-95685']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
