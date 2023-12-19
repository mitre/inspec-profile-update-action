control 'SV-223729' do
  title 'NIST FIPS-validated cryptography must be used to protect passwords in the security database.'
  desc 'Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that need to be tested before the password is compromised.

Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

'
  desc 'check', 'From the ISPF Command Shell enter:
SETRopts List

If the following is specified under PASSWORD PROCESSING OPTIONS: THE ACTIVE PASSWORD ENCRYPTION ALGORITHM IS KDFAES, this is not a finding.'
  desc 'fix', 'Evaluate the impact associated with implementation of the control option. Develop a plan of action to implement the control option as specified below:

For z/OS release 1.12 through z/OS release 2.1 APARs OA43998 and OA43999 must be applied.

Set the passwords option for algorithm to KDFAES.

Sample syntax to activate:
SETRopts PASSWORD(ALGORITHM(KDFAES))'
  impact 0.7
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25402r514875_chk'
  tag severity: 'high'
  tag gid: 'V-223729'
  tag rid: 'SV-223729r604139_rule'
  tag stig_id: 'RACF-ES-000820'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-25390r514876_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000074-GPOS-00042', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag legacy: ['V-98165', 'SV-107269']
  tag cci: ['CCI-000196', 'CCI-000197', 'CCI-000803']
  tag nist: ['IA-5 (1) (c)', 'IA-5 (1) (c)', 'IA-7']
end
