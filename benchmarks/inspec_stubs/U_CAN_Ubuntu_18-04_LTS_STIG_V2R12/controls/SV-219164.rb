control 'SV-219164' do
  title 'The Ubuntu operating system must enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.'
  desc 'Limiting the number of logon attempts over a certain time interval reduces the chances that an unauthorized user may gain access to an account.'
  desc 'check', 'Verify the Ubuntu operating system enforces a delay of at least 4 seconds between logon prompts following a failed logon attempt.

Check that the Ubuntu operating system enforces a delay of at least 4 seconds between logon prompts with the following command:

# grep pam_faildelay /etc/pam.d/common-auth

auth required pam_faildelay.so delay=4000000

If the line is not present, or is commented out, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to enforce a delay of at least 4 seconds between logon prompts following a failed logon attempt.

Edit the file "/etc/pam.d/common-auth" and set the parameter "pam_faildelay" to a value of 4000000 or greater:

auth required pam_faildelay.so delay=4000000'
  impact 0.3
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20889r304820_chk'
  tag severity: 'low'
  tag gid: 'V-219164'
  tag rid: 'SV-219164r610963_rule'
  tag stig_id: 'UBTU-18-010031'
  tag gtitle: 'SRG-OS-000480-GPOS-00226'
  tag fix_id: 'F-20888r304821_fix'
  tag 'documentable'
  tag legacy: ['V-100555', 'SV-109659']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
