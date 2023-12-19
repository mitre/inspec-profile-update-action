control 'SV-250642' do
  title 'The SSH client must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'DoD information systems are required to use FIPS 140-2 approved ciphers. SSHv2 ciphers meeting this requirement are 3DES and AES.'
  desc 'check', "Disable lock down mode.
Enable the ESXi Shell.

Check the SSH client configuration for allowed ciphers.

# grep -i ciphers /etc/ssh/ssh_config | grep -v '^#' 

If the returned ciphers list contains any cipher not starting with 3des or aes, this is a finding. If the /etc/ssh/ssh_config file does not exist or the Ciphers option is not set, this is not a finding.

Re-enable lock down mode."
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell.

Edit the SSH client configuration and add/modify the "Ciphers" configuration (example: 3des-ctr, aes128-ctr, aes192-ctr, aes256-ctr). # vi /etc/ssh/ssh_config

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54077r798923_chk'
  tag severity: 'medium'
  tag gid: 'V-250642'
  tag rid: 'SV-250642r798925_rule'
  tag stig_id: 'SRG-OS-000159-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54031r798924_fix'
  tag 'documentable'
  tag legacy: ['SV-51262', 'V-39404']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
