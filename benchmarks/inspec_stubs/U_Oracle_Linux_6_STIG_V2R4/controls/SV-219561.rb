control 'SV-219561' do
  title 'The Oracle Linux 6 operating system must implement DoD-approved encryption to protect the confidentiality of SSH connections.'
  desc 'Approved algorithms should impart some level of confidence in their implementation. These are also required for compliance.
The system will attempt to use the first cipher presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest cipher available to secure the SSH connection.'
  desc 'check', 'Only FIPS-approved ciphers should be used. To verify that only FIPS-approved ciphers are in use, run the following command: 

# grep -i Ciphers /etc/ssh/sshd_config

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

If any ciphers other than "aes256-ctr", "aes192-ctr", or "aes128-ctr" are listed, the order differs from the example above, the "Ciphers" keyword is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Limit the ciphers to those algorithms which are FIPS-approved. The following line in "/etc/ssh/sshd_config" demonstrates use of FIPS-approved ciphers: 

Ciphers 256-ctr,aes192-ctr,aes128-ctr

Note: The man page "sshd_config(5)" contains a list of supported ciphers.'
  impact 0.5
  ref 'DPMS Target Oracle Linux 6'
  tag check_id: 'C-21286r622245_chk'
  tag severity: 'medium'
  tag gid: 'V-219561'
  tag rid: 'SV-219561r744067_rule'
  tag stig_id: 'OL6-00-000243'
  tag gtitle: 'SRG-OS-000250'
  tag fix_id: 'F-21285r622246_fix'
  tag 'documentable'
  tag legacy: ['V-50807', 'SV-65013']
  tag cci: ['CCI-001453']
  tag nist: ['AC-17 (2)']
end
