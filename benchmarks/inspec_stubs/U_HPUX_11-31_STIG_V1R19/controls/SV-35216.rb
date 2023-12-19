control 'SV-35216' do
  title 'The SSH daemon must be configured to only use FIPS 140-2 approved ciphers.'
  desc 'DoD information systems are required to use FIPS 140-2 approved ciphers. SSHv2 ciphers meeting this requirement are 3DES and AES.'
  desc 'check', %q(Check the SSH daemon configuration for allowed ciphers. Note that keywords are case-insensitive and arguments (args) are case-sensitive. 

keyword=Ciphers
arg(s)=<comma separated cipher(s) of the form 3des-ctr or aes-NNN-ctr, NNN=128, 192 or 256>

Default values include: "aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,3des-cbc,arcfour,arcfour128,arcfour256blowfish-cbc,cast128-cbc".

For this check, all keyword values ending with the suffix "-cbc" are disallowed, IE: 3des-cbc. As the vendor does not currently support 3des-ctr, the only current allowed keyword values begin with the prefix "aes" and terminate with the suffix "-ctr".

Note: When the default "arg" value exactly matches the required "arg" value (see above), the <keyword=arg> entry is not required to exist (commented or uncommented) in the ssh (client) or sshd (server) configuration file. While not required, it is recommended that the configuration file(s) be populated with all keywords and assigned arg values as a means to explicitly document the ssh(d) binary's expected behavior.

Examine the file. 
# cat /opt/ssh/etc/sshd_config | tr '\011' ' ' | tr -s ' ' | sed -e 's/^[ \t]*//' | grep -v '^#' | egrep -i "ciphers"

All ciphers present in the returned ciphers line entry must be prefixed by 3des or aes and end with the suffix "-ctr" or this is a finding.)
  desc 'fix', 'Edit the configuration file and remove any ciphers that do not meet the following: 3des-ctr or aes-NNN-ctr (NNN=128, 192 or 256). 

If necessary, add the Ciphers entry with one or more of the above keyword values.'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36633r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22458'
  tag rid: 'SV-35216r1_rule'
  tag stig_id: 'GEN005505'
  tag gtitle: 'GEN005505'
  tag fix_id: 'F-32003r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
