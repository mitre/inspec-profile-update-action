control 'SV-204578' do
  title 'The Red Hat Enterprise Linux 7 operating system must implement DoD-approved encryption to protect the confidentiality of SSH connections.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.

By specifying a cipher list with the order of ciphers being in a “strongest to weakest” orientation, the system will automatically attempt to use the strongest cipher for securing SSH connections.

'
  desc 'check', 'Verify the operating system uses mechanisms meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.

The location of the "sshd_config" file may vary if a different daemon is in use.

Inspect the "Ciphers" configuration with the following command:

# grep -i ciphers /etc/ssh/sshd_config
Ciphers aes256-ctr,aes192-ctr,aes128-ctr

If any ciphers other than "aes256-ctr", "aes192-ctr", or "aes128-ctr" are listed, the order differs from the example above, the "Ciphers" keyword is missing, or the returned line is commented out, this is a finding.'
  desc 'fix', 'Configure SSH to use FIPS 140-2 approved cryptographic algorithms.

Add the following line (or modify the line to have the required value) to the "/etc/ssh/sshd_config" file (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).

Ciphers aes256-ctr,aes192-ctr,aes128-ctr

The SSH service must be restarted for changes to take effect.'
  impact 0.5
  ref 'DPMS Target Red Hat Enterprise Linux 7'
  tag check_id: 'C-4702r622305_chk'
  tag severity: 'medium'
  tag gid: 'V-204578'
  tag rid: 'SV-204578r603843_rule'
  tag stig_id: 'RHEL-07-040110'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-4702r622306_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173']
  tag 'documentable'
  tag legacy: ['V-72221', 'SV-86845']
  tag cci: ['CCI-000366', 'CCI-000803', 'CCI-000068']
  tag nist: ['CM-6 b', 'IA-7', 'AC-17 (2)']
end
