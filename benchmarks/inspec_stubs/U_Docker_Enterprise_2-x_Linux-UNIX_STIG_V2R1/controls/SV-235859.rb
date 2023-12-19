control 'SV-235859' do
  title 'Docker Enterprise TLS certificate authority (CA) certificate file ownership must be set to root:root.'
  desc 'Verify that the TLS CA certificate file (the file that is passed along with --TLScacert parameter) is owned and group-owned by root.

The TLS CA certificate file should be protected from any tampering. It is used to authenticate Docker server based on given CA certificate. Hence, it must be owned and group-owned by root to maintain the integrity of the CA certificate.
By default, the ownership and group-ownership for TLS CA certificate file is correctly set to root.'
  desc 'check', 'Ensure that TLS CA certificate file ownership is set to root:root.

Execute the below command to verify that the TLS CA certificate file is owned and group-owned by root:

stat -c %U:%G <path to TLS CA certificate file> 

If the TLS CA certificate permissions are not set to root:root, this is a finding.'
  desc 'fix', 'Set the ownership and group-ownership for the TLS CA certificate file to root.

Run the following command:
chown root:root <path to TLS CA certificate file>'
  impact 0.7
  ref 'DPMS Target Docker Enterprise 2-x Linux-UNIX'
  tag check_id: 'C-39078r627702_chk'
  tag severity: 'high'
  tag gid: 'V-235859'
  tag rid: 'SV-235859r627704_rule'
  tag stig_id: 'DKER-EE-005250'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-39041r627703_fix'
  tag 'documentable'
  tag legacy: ['SV-104893', 'V-95755']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
