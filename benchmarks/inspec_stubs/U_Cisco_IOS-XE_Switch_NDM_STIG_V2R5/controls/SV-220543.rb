control 'SV-220543' do
  title 'The Cisco switch must only store cryptographic representations of passwords.'
  desc 'Passwords need to be protected at all times, and encryption is the standard method for protecting passwords. If passwords are not encrypted, they can be plainly read (i.e., clear text) and easily compromised.

Network devices must enforce cryptographic representations of passwords when storing passwords in databases, configuration files, and log files. Passwords must be protected at all times; using a strong one-way hashing encryption algorithm with a salt is the standard method for providing a means to validate a password without having to store the actual password.

Performance and time required to access are factors that must be considered, and the one way hash is the most feasible means of securing the password and providing an acceptable measure of password security. If passwords are stored in clear text, they can be plainly read and easily compromised.

In many instances, verifying the user knows a password is performed using a password verifier. In its simplest form, a password verifier is a computational function that is capable of creating a hash of a password and determining if the value provided by the user matches the stored hash.'
  desc 'check', 'Review the switch configuration to determine if passwords are encrypted as shown in the example below:

service password-encryption
…
…
…
Enable secret 5 xxxxxxxxxxxxxxxxxxxxxxxxxx

If the switch is not configured to encrypt passwords, this is a finding.'
  desc 'fix', 'Configure the switch to encrypt all passwords:

SW4(config)#service password-encryption 
SW4(config)#enable secret xxxxxxxxxxxx
SW4(config)#end'
  impact 0.7
  ref 'DPMS Target Cisco IOS XE Switch NDM'
  tag check_id: 'C-22258r508573_chk'
  tag severity: 'high'
  tag gid: 'V-220543'
  tag rid: 'SV-220543r879608_rule'
  tag stig_id: 'CISC-ND-000620'
  tag gtitle: 'SRG-APP-000171-NDM-000258'
  tag fix_id: 'F-22247r508574_fix'
  tag 'documentable'
  tag legacy: ['SV-110541', 'V-101437']
  tag cci: ['CCI-000196']
  tag nist: ['IA-5 (1) (c)']
end
