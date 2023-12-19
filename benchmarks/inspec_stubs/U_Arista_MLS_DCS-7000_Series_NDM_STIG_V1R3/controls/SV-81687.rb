control 'SV-81687' do
  title 'The Arista Multilayer Switch must use FIPS-compliant mechanisms for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Network devices utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.'
  desc 'check', 'Review the device configuration via the “show running-config” command for the following statement:

management ssh
fips restrictions

If this statement is not present, this is a finding.'
  desc 'fix', 'Enable FIPS restrictions via the following commands:
Enable
Configure
Management ssh
Fips restrictions
Exit

Additionally, the switch should be configured to use its Hardware Random Number Generator as a source of entropy for the SSH protocol. To enable this, configure:

Enable
Configure
Management security
Entropy source hardware

Once this has been changed, regenerate the SSH RSA Keys with:

Reset ssh hostkey rsa'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series NDM'
  tag check_id: 'C-67775r1_chk'
  tag severity: 'medium'
  tag gid: 'V-67197'
  tag rid: 'SV-81687r1_rule'
  tag stig_id: 'AMLS-NM-200825'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-73309r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
