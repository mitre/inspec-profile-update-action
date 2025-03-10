control 'SV-217275' do
  title 'The SUSE operating system SSH daemon public host key files must have mode 0644 or less permissive.'
  desc 'If a public host key file is modified by an unauthorized user, the SSH service may be compromised.'
  desc 'check', %q(Verify the SUSE operating system SSH daemon public host key files have mode "0644" or less permissive.

Note: SSH public key files may be found in other directories on the system depending on the installation.

The following command will find all SSH public key files on the system:

> find /etc/ssh -name 'ssh_host*key.pub' -exec stat -c "%a %n" {} \;

644 /etc/ssh/ssh_host_rsa_key.pub
644 /etc/ssh/ssh_host_dsa_key.pub
644 /etc/ssh/ssh_host_ecdsa_key.pub
644 /etc/ssh/ssh_host_ed25519_key.pub

If any file has a mode more permissive than "0644", this is a finding.)
  desc 'fix', 'Configure the SUSE operating system SSH daemon public host key files have mode "0644" or less permissive.

Note: SSH public key files may be found in other directories on the system depending on the installation. 

Change the mode of public host key files under "/etc/ssh" to "0644" with the following command:

> sudo chmod 0644 /etc/ssh/ssh_host*key.pub'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18503r646748_chk'
  tag severity: 'medium'
  tag gid: 'V-217275'
  tag rid: 'SV-217275r646750_rule'
  tag stig_id: 'SLES-12-030210'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-18501r646749_fix'
  tag 'documentable'
  tag legacy: ['V-77463', 'SV-92159']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
