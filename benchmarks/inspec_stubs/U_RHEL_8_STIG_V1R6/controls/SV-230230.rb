control 'SV-230230' do
  title 'RHEL 8, for certificate-based authentication, must enforce authorized access to the corresponding private key.'
  desc 'If an unauthorized user obtains access to a private key without a passcode, that user would have unauthorized access to any system where the associated public key has been installed.'
  desc 'check', 'Verify the SSH private key files have a passcode.

For each private key stored on the system, use the following command:

$ sudo ssh-keygen -y -f /path/to/file

If the contents of the key are displayed, this is a finding.'
  desc 'fix', 'Create a new private and public key pair that utilizes a passcode with the following command:

$ sudo ssh-keygen -n [passphrase]'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 8'
  tag check_id: 'C-32899r567436_chk'
  tag severity: 'medium'
  tag gid: 'V-230230'
  tag rid: 'SV-230230r627750_rule'
  tag stig_id: 'RHEL-08-010100'
  tag gtitle: 'SRG-OS-000067-GPOS-00035'
  tag fix_id: 'F-32874r567437_fix'
  tag 'documentable'
  tag cci: ['CCI-000186']
  tag nist: ['IA-5 (2) (a) (1)']
end
