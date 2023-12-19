control 'SV-235009' do
  title 'The SUSE operating system SSH daemon private host key files must have mode 0640 or less permissive.'
  desc 'If an unauthorized user obtains the private SSH host key file, the host could be impersonated.'
  desc 'check', %q(Verify the SUSE operating system SSH daemon private host key files have mode "0640" or less permissive.

The following command will find all SSH private key files on the system:

     > sudo find / -name '*ssh_host*key' -exec ls -lL {} \;

Check the mode of the private host key files under "/etc/ssh" file with the following command:

     > find /etc/ssh -name 'ssh_host*key' -exec stat -c "%a %n" {} \;

     640 /etc/ssh/ssh_host_rsa_key
     640 /etc/ssh/ssh_host_dsa_key
     640 /etc/ssh/ssh_host_ecdsa_key
     640 /etc/ssh/ssh_host_ed25519_key

If any file has a mode more permissive than "0640", this is a finding.)
  desc 'fix', 'Configure the mode of the SUSE operating system SSH daemon private host key files under "/etc/ssh" to "0640" with the following command:

     > sudo chmod 0640 /etc/ssh/ssh_host*key'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38197r880956_chk'
  tag severity: 'medium'
  tag gid: 'V-235009'
  tag rid: 'SV-235009r880958_rule'
  tag stig_id: 'SLES-15-040250'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-38160r880957_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
