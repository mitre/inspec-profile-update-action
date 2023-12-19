control 'SV-48066' do
  title 'Unencrypted remote access to system services must not be permitted.'
  desc 'Unencrypted access to system services may permit user identification and passwords that are being transmitted in clear text to be intercepted.  This could provide an intruder access to the network.'
  desc 'check', 'Verify encryption is required for remote access.

If userid and password information are not encrypted, this is a finding.

If administrator data is not encrypted, this is a finding.

If user data coming from or going outside the enclave is not encrypted, this is a finding.'
  desc 'fix', 'Require encryption for remote access.

Encryption of userid and password information is always required.

Encryption of administrator data is always required.

Encryption of user data coming from or going outside the network firewall is required.

Encryption of the user data inside the network firewall is also highly recommended.'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44805r4_chk'
  tag severity: 'high'
  tag gid: 'V-2908'
  tag rid: 'SV-48066r2_rule'
  tag stig_id: 'WN08-00-000007'
  tag gtitle: 'Unencrypted Remote Access'
  tag fix_id: 'F-41204r4_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
