control 'SV-51202' do
  title 'Network infrastructure and systems supporting the test and development environment must be documented within the organizations accreditation package.'
  desc 'Up-to-date documentation is essential in assisting with the management, auditing, and security of the network infrastructure used to support the test and development environment.  Network diagrams are important because they show the overall layout where devices are physically located within the network infrastructure. Diagrams also show the relationship and connectivity between devices where possible intrusive attacks could take place.  Having up-to-date network diagrams will also help show what the security, traffic, and physical impact of adding a system will be on the network.'
  desc 'check', "Review the accreditation package documentation to verify the test and development environment is correctly documented within the network diagrams and site security plan.  If the organization's accreditation package does not include the test and development infrastructure in the network diagrams and system security plan, this is a finding."
  desc 'fix', 'Document network infrastructure and systems supporting the test and development environment, then include it with the accreditation package.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone B'
  tag check_id: 'C-46619r2_chk'
  tag severity: 'medium'
  tag gid: 'V-39344'
  tag rid: 'SV-51202r1_rule'
  tag stig_id: 'ENTD0010'
  tag gtitle: 'ENTD0010 - The test and development infrastructure is not properly documented.'
  tag fix_id: 'F-44359r2_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'Information Assurance Manager']
  tag ia_controls: 'DCHW-1'
end
