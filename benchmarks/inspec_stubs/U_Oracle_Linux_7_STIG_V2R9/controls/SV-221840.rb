control 'SV-221840' do
  title 'The Oracle Linux 7 operating system must implement DoD-approved encryption to protect the confidentiality of SSH connections.'
  desc 'Unapproved mechanisms for authentication to the cryptographic module are not verified, and therefore cannot be relied upon to provide confidentiality or integrity, resulting in the compromise of DoD data.

Operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.

The system will attempt to use the first cipher presented by the client that matches the server list. Listing the values "strongest to weakest" is a method to ensure the use of the strongest cipher available to secure the SSH connection.

'
  desc 'check', 'Verify the operating system uses mechanisms that meet the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.

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
  ref 'DPMS Target Oracle Linux 7'
  tag check_id: 'C-23555r622269_chk'
  tag severity: 'medium'
  tag gid: 'V-221840'
  tag rid: 'SV-221840r853717_rule'
  tag stig_id: 'OL07-00-040110'
  tag gtitle: 'SRG-OS-000033-GPOS-00014'
  tag fix_id: 'F-23544r622270_fix'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000120-GPOS-00061', 'SRG-OS-000125-GPOS-00065', 'SRG-OS-000250-GPOS-00093', 'SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag legacy: ['SV-108523', 'V-99419']
  tag cci: ['CCI-000068', 'CCI-000803', 'CCI-000877', 'CCI-002890', 'CCI-003123']
  tag nist: ['AC-17 (2)', 'IA-7', 'MA-4 c', 'MA-4 (6)', 'MA-4 (6)']
end
