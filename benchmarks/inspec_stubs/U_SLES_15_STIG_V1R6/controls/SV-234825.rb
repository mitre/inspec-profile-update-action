control 'SV-234825' do
  title 'The SUSE operating system must employ FIPS 140-2 approved cryptographic hashing algorithm for system authentication (login.defs).'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DoD data may be compromised.

SUSE operating systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DoD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.'
  desc 'check', 'Verify the SUSE operating system requires that the "ENCRYPT_METHOD" value in "/etc/login.defs" is set to "SHA512".

Check the value of "ENCRYPT_METHOD" value in "/etc/login.defs" with the following command:

> grep "^ENCRYPT_METHOD " /etc/login.defs

ENCRYPT_METHOD SHA512

If "ENCRYPT_METHOD" is not set to "SHA512", if any values other that "SHA512" are configured, or if no output is produced, this is a finding.'
  desc 'fix', 'Configure the SUSE operating system to require "ENCRYPT_METHOD" of "SHA512".

Edit the "/etc/login.defs" file with the following line:

ENCRYPT_METHOD SHA512'
  impact 0.5
  ref 'DPMS Target SUSE Linux Enterprise Server 15'
  tag check_id: 'C-38013r618744_chk'
  tag severity: 'medium'
  tag gid: 'V-234825'
  tag rid: 'SV-234825r622137_rule'
  tag stig_id: 'SLES-15-010260'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag fix_id: 'F-37976r618745_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
