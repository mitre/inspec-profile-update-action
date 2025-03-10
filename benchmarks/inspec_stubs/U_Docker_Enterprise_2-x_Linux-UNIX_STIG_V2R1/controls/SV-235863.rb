control 'SV-235863' do
  title 'Docker Enterprise server certificate key file ownership must be set to root:root.'
  desc 'Verify that the Docker server certificate key file (the file that is passed along with --TLSkey parameter) is owned and group-owned by root.

The Docker server certificate key file should be protected from any tampering or unneeded reads. It holds the private key for the Docker server certificate. Hence, it must be owned and group-owned by root to maintain the integrity of the Docker server certificate.

By default, the ownership and group-ownership for Docker server certificate key file is correctly set to root.'
  desc 'check', 'Ensure that Docker server certificate key file ownership is set to root:root.

Execute the below command to verify that the Docker server certificate key file is owned and group-owned by root:

stat -c %U:%G <path to Docker server certificate key file> 

If the certificate file is not owned by root:root, this is a finding.'
  desc 'fix', 'chown root:root <path to Docker server certificate key file>

This sets the ownership and group-ownership for the Docker server certificate key file to root.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39082r627714_chk'
  tag severity: 'medium'
  tag gid: 'V-235863'
  tag rid: 'SV-235863r627716_rule'
  tag stig_id: 'DKER-EE-005290'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39045r627715_fix'
  tag 'documentable'
  tag legacy: ['SV-104901', 'V-95763']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
