control 'SV-250640' do
  title 'The SSH client must be configured to not use CBC-based ciphers.'
  desc 'The Cipher-Block Chaining (CBC) mode of encryption as implemented in the SSHv2 protocol is vulnerable to chosen plain text attacks and must not be used.'
  desc 'check', "Disable lock down mode.
Enable the ESXi Shell.

 Check the SSH client configuration for allowed ciphers. # grep -i ciphers /etc/ssh/ssh_config | grep -v '^#' 

Re-enable lock down mode.

 If the returned ciphers list contains any cipher ending with cbc, this is a finding.  If the /etc/ssh/ssh_config file does not exist or the Ciphers option is not set, this is not a finding."
  desc 'fix', 'Disable lock down mode.
Enable the ESXi Shell.

Edit the SSH client configuration and add/modify the "Ciphers" configuration (examples of disallowed ciphers:  aes128-cbc, aes192-cbc, aes256-cbc, arcfour256blowfish-cbc, cast128-cbc, 3des-cbc).
# vi /etc/ssh/ssh_config

Re-enable lock down mode.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54075r798917_chk'
  tag severity: 'medium'
  tag gid: 'V-250640'
  tag rid: 'SV-250640r798919_rule'
  tag stig_id: 'SRG-OS-000157-ESXI5'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54029r798918_fix'
  tag 'documentable'
  tag legacy: ['SV-51260', 'V-39402']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
