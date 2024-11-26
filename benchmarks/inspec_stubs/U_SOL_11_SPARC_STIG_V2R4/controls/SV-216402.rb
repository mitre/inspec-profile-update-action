control 'SV-216402' do
  title 'The operating system must use mechanisms for authentication to a cryptographic module meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance for such authentication.'
  desc 'Encryption is only as good as the encryption modules utilized. Unapproved cryptographic module algorithms cannot be verified, and cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised due to weak algorithms. 

Applications utilizing encryption are required to use approved encryption modules meeting the requirements of applicable federal laws, Executive orders, directives, policies, regulations, standards, and guidance. 

FIPS 140-2 is the current standard for validating cryptographic modules, and NSA Type-X (where X=1, 2, 3, 4) products are NSA-certified hardware based encryption modules.

'
  desc 'check', 'This check applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this check applies.

The Crypto Management profile is required to execute this command.

Check to ensure that FIPS-140 encryption mode is enabled.

# cryptoadm list fips-140| grep -c "is disabled"

If the output of this command is not "0", this is a finding.'
  desc 'fix', 'The Crypto Management profile is required to execute this command.

This action applies to the global zone only. Determine the zone that you are currently securing.

# zonename

If the command output is "global", this action applies.

Enable FIPS-140 mode.

# pfexec cryptoadm enable fips-140

Reboot the system as requested.'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17638r371294_chk'
  tag severity: 'medium'
  tag gid: 'V-216402'
  tag rid: 'SV-216402r603267_rule'
  tag stig_id: 'SOL-11.1-060010'
  tag gtitle: 'SRG-OS-000481'
  tag fix_id: 'F-17636r371295_fix'
  tag satisfies: ['SRG-OS-000120', 'SRG-OS-000169']
  tag 'documentable'
  tag legacy: ['V-48187', 'SV-61059']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
