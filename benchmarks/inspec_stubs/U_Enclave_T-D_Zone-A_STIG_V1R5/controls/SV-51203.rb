control 'SV-51203' do
  title 'Network infrastructure and systems supporting the test and development environment must follow DoD certification and accreditation procedures before connecting to a DoD operational network or Internet Service Provider.'
  desc 'Prior to connecting to a live operational network, such as the DISN, systems, at minimum, receive an IATO.  A system without an IATO does not show adequate effort to meet IA controls and security requirements and may pose a risk to other computers or systems connecting to the operational network.'
  desc 'check', 'Review the accreditation package documentation to verify the test and development environment has been granted an IATO to connect to the DISN.  If an IATO has not been granted, this is a finding. 

If the zone environment does not have any connectivity to the DISN or commercial ISP, this requirement is not applicable.'
  desc 'fix', "Certify and accredit the test and development infrastructure and supporting systems connecting to the DISN.  Keep the IATO with the organization's accreditation package."
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone A'
  tag check_id: 'C-46707r5_chk'
  tag severity: 'medium'
  tag gid: 'V-39345'
  tag rid: 'SV-51203r1_rule'
  tag stig_id: 'ENTD0020'
  tag gtitle: 'ENTD0020 - The test and development infrastructure does not follow a CAP.'
  tag fix_id: 'F-44662r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Manager', 'Information Assurance Officer']
  tag ia_controls: 'EBCR-1'
end
