control 'SV-225204' do
  title 'The macOS system must issue or obtain public key certificates under an appropriate certificate policy from an approved service provider.'
  desc 'DoD-approved certificates must be installed to the System Keychain so they will be available to all users.

For user certificates, each organization obtains certificates from an approved, shared service provider, as required by OMB policy. For federal agencies operating a legacy public key infrastructure cross-certified with the Federal Bridge Certification Authority at medium assurance or higher, this Certification Authority will suffice. This control focuses on certificates with a visibility external to the information system and does not include certificates related to internal system operations; for example, application-specific time services. Use of weak or untested encryption algorithms undermines the purposes of utilizing encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

'
  desc 'check', %q(To view a list of installed certificates, run the following command:

/usr/bin/sudo /usr/bin/security dump-keychain | /usr/bin/grep labl | awk -F\" '{ print $4 }'

If this list does not contain approved certificates, this is a finding.)
  desc 'fix', 'Obtain the approved DOD certificates from the appropriate authority. Use Keychain Access from "/Applications/Utilities" to add certificates to the System Keychain.'
  impact 0.7
  ref 'DPMS Target Apple OS X 10.15'
  tag check_id: 'C-26903r467780_chk'
  tag severity: 'high'
  tag gid: 'V-225204'
  tag rid: 'SV-225204r610901_rule'
  tag stig_id: 'AOSX-15-003001'
  tag gtitle: 'SRG-OS-000066-GPOS-00034'
  tag fix_id: 'F-26891r467781_fix'
  tag satisfies: ['SRG-OS-000066-GPOS-00034', 'SRG-OS-000478-GPOS-00223']
  tag 'documentable'
  tag legacy: ['V-102827', 'SV-111789']
  tag cci: ['CCI-000185', 'CCI-002450']
  tag nist: ['IA-5 (2) (b) (1)', 'SC-13 b']
end
