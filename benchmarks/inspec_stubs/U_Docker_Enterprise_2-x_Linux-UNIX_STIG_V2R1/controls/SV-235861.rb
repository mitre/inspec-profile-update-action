control 'SV-235861' do
  title 'Docker Enterprise server certificate file ownership must be set to root:root.'
  desc 'Verify that the Docker server certificate file (the file that is passed along with --TLScert parameter) is owned and group-owned by root.

The Docker server certificate file should be protected from any tampering. It is used to authenticate Docker server based on the given server certificate. Hence, it must be owned and group-owned by root to maintain the integrity of the certificate.

By default, the ownership and group-ownership for Docker server certificate file is correctly set to root.'
  desc 'check', 'Ensure that Docker server certificate file ownership is set to root:root.

Execute the below command to verify that the Docker server certificate file is owned and group-owned by root:

stat -c %U:%G <path to Docker server certificate file> 

If the command does not return root:root, this is a finding.'
  desc 'fix', 'chown root:root <path to Docker server certificate file>

This sets the ownership and group-ownership for the Docker server certificate file to root.'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39080r627708_chk'
  tag severity: 'high'
  tag gid: 'V-235861'
  tag rid: 'SV-235861r627710_rule'
  tag stig_id: 'DKER-EE-005270'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39043r627709_fix'
  tag 'documentable'
  tag legacy: ['SV-104897', 'V-95759']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
