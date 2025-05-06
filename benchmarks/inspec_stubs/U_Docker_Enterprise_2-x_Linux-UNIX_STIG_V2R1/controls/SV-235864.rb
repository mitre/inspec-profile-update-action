control 'SV-235864' do
  title 'Docker Enterprise server certificate key file permissions must be set to 400.'
  desc 'Verify that the Docker server certificate key file (the file that is passed along with --TLSkey parameter) has permissions of 400.

The Docker server certificate key file should be protected from any tampering or unneeded reads. It holds the private key for the Docker server certificate. Hence, it must have permissions of 400 to maintain the integrity of the Docker server certificate.

By default, the permissions for Docker server certificate key file might not be 400. The default file permissions are governed by the system or user specific umask values.'
  desc 'check', 'Ensure that Docker server certificate key file permissions are set to 400.

Execute the below command to verify that the Docker server certificate key file has permissions of 400:

stat -c %a <path to Docker server certificate key file>

If the permissions are not set to 400, this is a finding.'
  desc 'fix', 'Set the Docker server certificate key file permissions to 400.

Run the following command:
chmod 400 <path to Docker server certificate key file>'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39083r627717_chk'
  tag severity: 'high'
  tag gid: 'V-235864'
  tag rid: 'SV-235864r627719_rule'
  tag stig_id: 'DKER-EE-005300'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39046r627718_fix'
  tag 'documentable'
  tag legacy: ['SV-104903', 'V-95765']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
