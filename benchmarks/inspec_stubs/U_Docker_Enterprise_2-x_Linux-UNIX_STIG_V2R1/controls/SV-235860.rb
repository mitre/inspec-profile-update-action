control 'SV-235860' do
  title 'Docker Enterprise TLS certificate authority (CA) certificate file permissions must be set to 444 or more restrictive.'
  desc 'Verify that the TLS CA certificate file (the file that is passed along with --TLScacert parameter) has permissions of 444 or more restrictive.

The TLS CA certificate file should be protected from any tampering. It is used to authenticate Docker server based on given CA certificate. Hence, it must have permissions of 444 to maintain the integrity of the CA certificate.

By default, the permissions for TLS CA certificate file might not be 444. The default file permissions are governed by the system or user specific umask values.'
  desc 'check', 'Ensure that TLS CA certificate file permissions are set to 444 or more restrictive.

Execute the below command to verify that the TLS CA certificate file has permissions of 444 or more restrictive:

stat -c %a <path to TLS CA certificate file>

If the permissions are not set to 444, this is a finding.'
  desc 'fix', 'chmod 444 <path to TLS CA certificate file>

This sets the file permissions of the TLS CA file to 444.'
  impact 0.5
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39079r627705_chk'
  tag severity: 'medium'
  tag gid: 'V-235860'
  tag rid: 'SV-235860r627707_rule'
  tag stig_id: 'DKER-EE-005260'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39042r627706_fix'
  tag 'documentable'
  tag legacy: ['SV-104895', 'V-95757']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
