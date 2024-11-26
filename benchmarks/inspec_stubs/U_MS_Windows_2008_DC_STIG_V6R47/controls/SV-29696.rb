control 'SV-29696' do
  title 'Unencrypted remote access is permitted to system services.'
  desc 'This is a category 1 finding because when unencrypted access to system services is permitted, an intruder can intercept user identification and passwords that are being transmitted in clear text.  This could give an intruder unlimited access to the network.'
  desc 'check', 'Interview the IAO to ensure that encryption of userid and password information is required, and data is encrypted according to DoD policy.

If the user account used for unencrypted remote access within the enclave (premise router) has administrator privileges, then this is a finding.

If userid and password information used for remote access to system services from outside the enclave is not encrypted, then this is a finding.'
  desc 'fix', 'Encryption of userid and password information is required.

Encryption of the user data inside the network firewall is also highly recommended.  

Encryption of user data coming from or going outside the network firewall is required. 

Encryption for administrator data is always required.  

Refer to the Enclave Security STIG section on “FTP and Telnet,” for detailed information on its use.'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-7892r1_chk'
  tag severity: 'high'
  tag gid: 'V-2908'
  tag rid: 'SV-29696r1_rule'
  tag gtitle: 'Unencrypted Remote Access'
  tag fix_id: 'F-120r1_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
