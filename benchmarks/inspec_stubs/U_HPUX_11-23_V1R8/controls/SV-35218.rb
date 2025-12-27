control 'SV-35218' do
  title 'The SSH daemon must be configured to not use Cipher-Block Chaining (CBC) ciphers.'
  desc 'The CBC mode of encryption as implemented in the SSHv2 protocol is vulnerable to chosen plaintext attacks and must not be used.'
  desc 'check', %q(Check the SSH daemon configuration for allowed ciphers. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword=Ciphers
arg(s)=<comma separated cipher(s)>

Default values include: "aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,3des-cbc,arcfour,arcfour128,arcfour256blowfish-cbc,cast128-cbc".

For this check, the only allowed keyword values are those from the above list with the "aes" prefix and the "-ctr" suffix.

Note: When the default "arg" value exactly matches the required "arg" value (see above), the <keyword=arg> entry is not required to exist (commented or uncommented) in the ssh (client) or sshd (server) configuration file. While not required, it is recommended that the configuration file(s) be populated with all keywords and assigned arg values as a means to explicitly document the ssh(d) binary's expected behavior.

Examine the file. 
# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | grep -i "ciphers"

If the returned ciphers list contains any cipher other than those with the "aes" prefix and the "-ctr" suffix, this is a finding.)
  desc 'fix', 'Edit the configuration file and remove any ciphers other than those with the "aes" prefix and the "-ctr" suffix.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.23'
  tag check_id: 'C-36634r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22459'
  tag rid: 'SV-35218r1_rule'
  tag stig_id: 'GEN005506'
  tag gtitle: 'GEN005506'
  tag fix_id: 'F-32004r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
