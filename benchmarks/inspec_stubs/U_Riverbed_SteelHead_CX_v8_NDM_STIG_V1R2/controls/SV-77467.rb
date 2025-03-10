control 'SV-77467' do
  title 'Riverbed Optimization System (RiOS) must use mechanisms meeting the requirements of applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance for authentication to a cryptographic module.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied upon to provide confidentiality or integrity, and DoD data may be compromised.

Network devices utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-2 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DoD requirements.

Note that adding the FIPS 140-2 licenses incurs a cost from the vendor for support for FIPS mode/module.'
  desc 'check', 'Verify that RiOS is licensed to use FIPS 140-2 cryptographic modules.

Navigate to the device CLI
Type: enable
Type: config t
Type: show licenses

Verify installation of a FIPS License

Type: show web ssl cipher
Verify that the web ssl cipher string is:
"TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL"

If a FIPS license is not present and the web ssl cipher string is not set properly, this is a finding.'
  desc 'fix', 'Configure RiOS to be licenses to use FIPS 140-2 cryptographic modules.

Navigate to the device CLI
Type: enable
Type: config t
Type: license install <license-string>

Type: web ssl cipher TLSv1.2+FIPS:kRSA+FIPS:!eNULL:!aNULL

Type: write memory

Verify license installation
Type: show licenses

Type: show web ssl cipher'
  impact 0.5
  ref 'DPMS Target Riverbed SteelHead CX Version 8 NDM'
  tag check_id: 'C-63729r1_chk'
  tag severity: 'medium'
  tag gid: 'V-62977'
  tag rid: 'SV-77467r1_rule'
  tag stig_id: 'RICX-DM-000130'
  tag gtitle: 'SRG-APP-000179-NDM-000265'
  tag fix_id: 'F-68895r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
