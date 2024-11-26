control 'SV-235862' do
  title 'Docker Enterprise server certificate file permissions must be set to 444 or more restrictive.'
  desc 'Verify that the Docker server certificate file (the file that is passed along with --TLScert parameter) has permissions of 444 or more restrictive.

The Docker server certificate file should be protected from any tampering. It is used to authenticate Docker server based on the given server certificate. Hence, it must have permissions of 444 to maintain the integrity of the certificate.

By default, the permissions for Docker server certificate file might not be 444. The default file permissions are governed by the system or user specific umask values.'
  desc 'check', 'Ensure that Docker server certificate file permissions are set to 444 or more restrictive.

Execute the below command to verify that the Docker server certificate file has permissions of 444 or more restrictive:

stat -c %a <path to Docker server certificate file>

If the permissions are not set to 444, this is a finding.'
  desc 'fix', 'chmod 444 <path to Docker server certificate file>

This sets the file permissions of the Docker server file to 444.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39081r627711_chk'
  tag severity: 'medium'
  tag gid: 'V-235862'
  tag rid: 'SV-235862r627713_rule'
  tag stig_id: 'DKER-EE-005280'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39044r627712_fix'
  tag 'documentable'
  tag legacy: ['SV-104899', 'V-95761']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
