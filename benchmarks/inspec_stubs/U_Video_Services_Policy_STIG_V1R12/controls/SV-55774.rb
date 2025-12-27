control 'SV-55774' do
  title 'An ISDN-based VTC system supporting secure (classified) and non-secure (unclassified) conferences must be cabled to maintain a minimum of 5 or 15 centimeters RED/BLACK separation on either side of any Type 1 encryptor and any dial isolator (depending on the TEMPEST zone).'
  desc 'Information leakage is the intentional or unintentional release of information to an untrusted environment from electromagnetic signals emanations. Security categories or classifications of information systems (with respect to confidentiality) and organizational security policies guide the selection of security controls employed to protect systems against information leakage due to electromagnetic signals emanations. The Committee on National Security Systems Advisory Memorandum (CNSSAM) TEMPEST/01-13, RED/BLACK Installation Guidance, provides criteria for the installation of electronic equipment, cabling, and facility support for the processing of secure information.

The TEMPEST/01-13 requires separation between RED and BLACK equipment and cables, to include cable routing inside equipment cabinets. Depending on TEMPEST ZONE, the separation requirements are:
- Minimum equipment separation - 50 cm or 1m
- Minimum cable separation - 5 cm or 15 cm

The unencrypted information, wiring, and processing equipment are considered RED while the encrypted information, wiring, and processing equipment are considered BLACK.'
  desc 'check', 'Review the documentation and based on the TEMPEST ZONE in the CNSSAM TEMPEST/01-13, RED/BLACK Installation Guidance, verify whether the required separations between RED and BLACK equipment and cables are met. This includes cable routing inside equipment cabinets. Depending on the TEMPEST ZONE, the separation requirements are:
- Minimum equipment separation - 50 cm or 1m
- Minimum cable separation - 5 cm or 15 cm

If the cables or equipment are closer than the minimum cable and equipment separation distances, this is a finding.'
  desc 'fix', 'Install cabling and equipment in accordance with CNSSAM TEMPEST/01-13, RED/BLACK Installation Guidance. Depending on the TEMPEST ZONE, the separation requirements are:
- Minimum equipment separation - 50 cm or 1m
- Minimum cable separation - 5 cm or 15 cm'
  impact 0.3
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49192r5_chk'
  tag severity: 'low'
  tag gid: 'V-43045'
  tag rid: 'SV-55774r2_rule'
  tag stig_id: 'RTS-VTC 7400'
  tag gtitle: 'RTS-VTC 7400'
  tag fix_id: 'F-48625r3_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECTC-1'
end
