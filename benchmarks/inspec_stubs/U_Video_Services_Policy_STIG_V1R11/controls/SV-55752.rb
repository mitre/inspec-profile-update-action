control 'SV-55752' do
  title 'The A/B, A/B/C, or A/B/C/D switch used for network switching in IP-based VTC systems implementing a single CODEC supporting conferences on multiple networks having different classification levels must be TEMPEST certified.'
  desc 'Committee on National Security Systems Advisory Memorandum (CNSSAM) TEMPEST/01-13, RED/BLACK Installation Guidance, provides criteria for the installation of electronic equipment, cabling, and facility support for the processing of secure information. National policy requires that systems and facilities processing NSI must be reviewed by a Certified TEMPEST Technical Authority (CTTA) to achieve TEMPEST security. The RED/BLACK guidance contained in TEMPEST/01-13will be considered by the CTTA along with other measures (e.g., TEMPEST Zoning, TEMPEST-suppressed equipment and shielding) to determine the most cost-effective countermeasures to achieve TEMPEST security. Only those RED/BLACK criteria specifically identified by the CTTA will be implemented.'
  desc 'check', 'Review the documentation to verify whether the A/B, A/B/C, or A/B/C/D switch is TEMPEST certified. Review TEMPEST certification documentation provided by a CTTA or the vendor to validate if the switch is TEMPEST certified. If the A/B, A/B/C, or A/B/C/D switch is not on the list, or satisfactory documentation is not provided, this is a finding.'
  desc 'fix', 'Obtain and install a TEMPEST-certified A/B, A/B/C, or A/B/C/D switch.'
  impact 0.3
  ref 'DPMS Target VTC Endpoint Site/System/Enclave'
  tag check_id: 'C-49180r8_chk'
  tag severity: 'low'
  tag gid: 'V-43023'
  tag rid: 'SV-55752r2_rule'
  tag stig_id: 'RTS-VTC 7160'
  tag gtitle: 'RTS-VTC 7160'
  tag fix_id: 'F-48607r2_fix'
  tag 'documentable'
  tag responsibility: 'Information Assurance Officer'
  tag ia_controls: 'ECTC-1'
end
