control 'SV-217122' do
  title 'The SUSE operating system must employ FIPS 140-2 approved cryptographic hashing algorithm for system authentication (login.defs).'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised.

SUSE operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.'
  desc 'check', 'Verify the SUSE operating system requires that the "ENCRYPT_METHOD" value in "/etc/login.defs" is set to "SHA512".

Check the value of "ENCRYPT_METHOD" value in "/etc/login.defs" with the following command:

> grep "^ENCRYPT_METHOD " /etc/login.defs

ENCRYPT_METHOD SHA512

If "ENCRYPT_METHOD" is not set to "SHA512", if any values other that "SHA512" are configured, or if no output is produced, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to require "ENCRYPT_METHOD" of "SHA512".

Edit the "/etc/login.defs" file with the following line:

ENCRYPT_METHOD SHA512'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 12'
  tag check_id: 'C-18350r646687_chk'
  tag severity: 'medium'
  tag gid: 'V-217122'
  tag rid: 'SV-217122r646689_rule'
  tag stig_id: 'SLES-12-010210'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-18348r646688_fix'
  tag 'documentable'
  tag legacy: ['V-77093', 'SV-91789']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
