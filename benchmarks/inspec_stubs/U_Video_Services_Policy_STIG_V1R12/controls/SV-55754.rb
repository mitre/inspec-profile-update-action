control 'SV-55754' do
  title 'The implementation of an IP-based VTC system supporting conferences on multiple networks having different classification levels must maintain isolation between the networks to which it connects by implementing separation of equipment and cabling between the various networks having differing classification levels in accordance with CNSSAM TEMPEST/01-13, RED/BLACK Installation Guidance.'
  desc 'Information leakage is the intentional or unintentional release of information to an untrusted environment from electromagnetic signals emanations. Security categories or classifications of information systems (with respect to confidentiality) and organizational security policies guide the selection of security controls employed to protect systems against information leakage due to electromagnetic signals emanations. The Committee on National Security Systems Advisory Memorandum (CNSSAM) TEMPEST/01-13, RED/BLACK Installation Guidance, provides criteria for the installation of electronic equipment, cabling, and facility support for the processing of secure information.

The TEMPEST/01-13 requires the facility housing the secure VTC equipment (i.e., the secure conference room) must meet the TEMPEST requirements for such rooms. The appropriate and required separations between RED and BLACK equipment and cables must be met. This includes cable routing inside equipment cabinets. Depending on the TEMPEST ZONE, the separation requirements are:
- Minimum equipment separation - 50 cm or 1m
- Minimum cable separation - 5 cm or 15 cm

National policy requires that systems and facilities processing NSI must be reviewed by a Certified TEMPEST Technical Authority (CTTA) to achieve TEMPEST security. The CTTA may require separate power sources for RED equipment and BLACK equipment.'
  desc 'check', 'Review the documentation and based on the TEMPEST ZONE in the CNSSAM TEMPEST/01-13, RED/BLACK Installation Guidance, verify whether the required separations between RED and BLACK equipment and cables have been met. This includes cable routing inside equipment cabinets. Depending on the TEMPEST ZONE, the separation requirements are:
- Minimum equipment separation - 50 cm or 1m
- Minimum cable separation - 5 cm or 15 cm

If the cables or equipment are closer than the minimum cable and equipment separation distances, this is a finding.

In the event a CTTA has reviewed the system’s installation and provided a favorable report or certification, this is not a finding.'
  desc 'fix', 'Install cabling and equipment in accordance with the CNSSAM TEMPEST/01-13, RED/BLACK Installation Guidance. 
Depending on the TEMPEST ZONE, the separation requirements are: 
- Minimum equipment separation - 50 cm or 1m
- Minimum cable separation - 5 cm or 15 cm'
  impact 0.5
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49182r7_chk'
  tag severity: 'medium'
  tag gid: 'V-43025'
  tag rid: 'SV-55754r2_rule'
  tag stig_id: 'RTS-VTC 7200'
  tag gtitle: 'RTS-VTC 7200'
  tag fix_id: 'F-48609r5_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECTC-1'
end
