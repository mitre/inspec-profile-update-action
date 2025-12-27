control 'SV-218004' do
  title 'The RHEL 6 operating system must implement DoD-approved encryption to protect the confidentiality of SSH connections.'
  desc 'Approved algorithms should impart some level of confidence in their implementation. These are also required for compliance.

By specifying a cipher list with the order of ciphers being in a “strongest to weakest” orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.'
  desc 'check', 'Only FIPS-approved ciphers should be used. To verify that only FIPS-approved ciphers are in use, run the following command: 

# grep -i Ciphers /etc/ssh/sshd_config

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

If any ciphers other than "aes256-ctr", "aes192-ctr", or "aes128-ctr" are listed, the order differs from the example above, the "Ciphers" keyword is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Limit the ciphers to those algorithms which are FIPS-approved. The following line in "/etc/ssh/sshd_config" demonstrates use of FIPS-approved ciphers: 

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

Note: The man page "sshd_config(5)" contains a list of supported ciphers.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 6'
  tag check_id: 'C-19485r603820_chk'
  tag severity: 'medium'
  tag gid: 'V-218004'
  tag rid: 'SV-218004r603822_rule'
  tag stig_id: 'RHEL-06-000243'
  tag gtitle: 'SRG-OS-000033'
  tag fix_id: 'F-19483r603821_fix'
  tag 'documentable'
  tag legacy: ['V-38617', 'SV-50418']
  tag cci: ['CCI-000068']
  tag nist: ['AC-17 (2)']
end
