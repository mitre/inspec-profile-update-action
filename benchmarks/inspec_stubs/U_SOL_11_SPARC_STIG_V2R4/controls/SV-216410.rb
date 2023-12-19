control 'SV-216410' do
  title 'The operating system must implement DoD-approved encryption to protect the confidentiality of remote access sessions.'
  desc 'Remote access is any access to an organizational information system by a user (or an information system) communicating through an external, non-organization-controlled network (e.g., the Internet). Examples of remote access methods include dial-up, broadband, and wireless. 

Using cryptography ensures confidentiality of the remote access connections.

The system will attempt to use the first cipher presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest cipher available to secure the SSH connection.

Note:  SSH in Solaris 11.GA-11.3 used Sun Microsystem’s proprietary SUNWssh. In Solaris 11.3 OpenSSH was offered as optional software and in Solaris 11.4 OpenSSH is the only SSH offered. Both use the same /etc/ssh/sshd_config file and both, by default do not include the ciphers line.'
  desc 'check', %q(Check the SSH daemon configuration for allowed ciphers.
 
# grep -i ciphers /etc/ssh/sshd_config | grep -v '^#’ 
Ciphers  aes256-ctr,aes192-ctr,aes128-ctr 
 
If any ciphers other than "aes256-ctr", "aes192-ctr", or "aes128-ctr" are listed, the order differs from the example above, the "Ciphers" keyword is missing, or is commented out, this is a finding.)
  desc 'fix', 'The root role is required. 

Modify the sshd_config file. 

# pfedit /etc/ssh/sshd_config 

Change or set the ciphers line to the following:

ciphers aes256-ctr,aes192-ctr,aes128-ctr 

Restart the SSH service. 

# svcadm restart svc:/network/ssh'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17646r622328_chk'
  tag severity: 'medium'
  tag gid: 'V-216410'
  tag rid: 'SV-216410r744132_rule'
  tag stig_id: 'SOL-11.1-060130'
  tag gtitle: 'SRG-OS-000033'
  tag fix_id: 'F-17644r622329_fix'
  tag 'documentable'
  tag legacy: ['V-48159', 'SV-61031']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
