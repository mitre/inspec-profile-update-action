control 'SV-101299' do
  title 'The Juniper router must be configured with a master password that is used to generate encrypted keys for shared secrets.'
  desc 'By default, shared secrets in a Junos configuration only use an obfuscation algorithm ($9$ format), which is not very strong and can easily be decrypted. Strong encryption for configured secrets can be enabled by configuring a master password to be used as input to the password based key derivation function (PBKDF2) to generate an encryption key. The key is used as input to the Advanced Encryption Standard in Galois/Counter Mode (AES256-GCM).'
  desc 'check', 'Verify that a master password has been configured as by entering the following command:
show configuration system master-password 

The output will appear as follows: 
password-configured;

Note: The master password is hidden from the configuration.

If a master password has not been configured, this is a finding.'
  desc 'fix', 'Configure the master password to be used to generate encrypted keys for shared secrets as shown in the example below.

[edit]
set system master-password plain-text-password    
Master password: xxxxxxxxxx
Repeat master password: xxxxxxxxxx'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-90353r2_chk'
  tag severity: 'medium'
  tag gid: 'V-91199'
  tag rid: 'SV-101299r1_rule'
  tag stig_id: 'JUNI-ND-001460'
  tag gtitle: 'SRG-APP-000516-NDM-000317'
  tag fix_id: 'F-97397r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
