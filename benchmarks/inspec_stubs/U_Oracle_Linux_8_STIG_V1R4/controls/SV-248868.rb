control 'SV-248868' do
  title 'OL 8 must force a frequent session key renegotiation for SSH connections to the server.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised. 
 
Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 
 
Session key regeneration limits the chances of a session key becoming compromised.'
  desc 'check', 'Verify the SSH server is configured to force frequent session key renegotiation with the following command:

$ sudo grep -ir RekeyLimit /etc/ssh/sshd_config*

RekeyLimit 1G 1h

If "RekeyLimit" does not have a maximum data amount and maximum time defined or is missing or commented out, this is a finding.
If conflicting results are returned, this is a finding.'
  desc 'fix', 'Configure the system to force a frequent session key renegotiation for SSH connections to the server by adding or modifying the following line in the "/etc/ssh/sshd_config" file: 
 
RekeyLimit 1G 1h 
 
The SSH daemon must be restarted for the settings to take effect. 
 
$ sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52302r858585_chk'
  tag severity: 'medium'
  tag gid: 'V-248868'
  tag rid: 'SV-248868r858586_rule'
  tag stig_id: 'OL08-00-040161'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-52256r780169_fix'
  tag 'documentable'
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
