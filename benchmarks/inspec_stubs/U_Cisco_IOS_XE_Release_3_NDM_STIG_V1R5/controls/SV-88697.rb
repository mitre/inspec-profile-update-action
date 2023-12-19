control 'SV-88697' do
  title 'The Cisco IOS XE router must store only encrypted representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Network devices must enforce password encryption when storing passwords.'
  desc 'check', 'Verify that Cisco IOS XE router has password encryption enabled.

The configuration should look similar to the example below:

password encryption aes
service password-encryption

If password encryption is not enabled, this is a finding.'
  desc 'fix', 'Add the following command to encrypt local passwords:

service password-encryption'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE NDM'
  tag check_id: 'C-74113r3_chk'
  tag severity: 'medium'
  tag gid: 'V-74023'
  tag rid: 'SV-88697r2_rule'
  tag stig_id: 'CISR-ND-000062'
  tag gtitle: 'SRG-APP-000171-NDM-000258'
  tag fix_id: 'F-80565r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
