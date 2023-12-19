control 'SV-219307' do
  title 'The Ubuntu operating system must implement DoD-approved encryption to protect the confidentiality of remote access sessions.'
  desc 'Without confidentiality protection mechanisms, unauthorized individuals may gain access to sensitive information via a remote access session.

Remote access is access to DoD nonpublic information systems by an authorized user (or an information system) communicating through an external, non-organization-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Encryption provides a means to secure the remote connection to prevent unauthorized access to the data traversing the remote access connection (e.g., RDP), thereby providing a degree of confidentiality. The encryption strength of a mechanism is selected based on the security categorization of the information.

By specifying a cipher list with the order of ciphers being in a “strongest to weakest” orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.'
  desc 'check', %q(Verify the SSH daemon is configured to only implement DoD-approved encryption.

Check the SSH daemon's current configured ciphers by running the following command:

# grep -E '^Ciphers ' /etc/ssh/sshd_config

Ciphers aes256-ctr,aes192-ctr, aes128-ctr

If any ciphers other than "aes256-ctr", "aes192-ctr", or "aes128-ctr" are listed, the order differs from the example above, the "Ciphers" keyword is missing, or the returned line is commented out, this is a finding.)
  desc 'fix', 'Configure the Ubuntu operating system to allow the SSH daemon to only implement DoD-approved encryption.

Add the following line (or modify the line to have the required value) to the "/etc/ssh/sshd_config" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor):

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

In order for the changes to take effect, the SSH daemon must be restarted.

# sudo systemctl restart sshd.service'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-21032r621653_chk'
  tag severity: 'medium'
  tag gid: 'V-219307'
  tag rid: 'SV-219307r610963_rule'
  tag stig_id: 'UBTU-18-010411'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-21031r621654_fix'
  tag 'documentable'
  tag legacy: ['SV-109941', 'V-100837']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
