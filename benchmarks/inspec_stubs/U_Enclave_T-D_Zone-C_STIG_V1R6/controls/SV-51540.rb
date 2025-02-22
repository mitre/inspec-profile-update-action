control 'SV-51540' do
  title 'Organizations interconnecting test and development environments must have MOAs, MOUs, and SLAs properly documented.'
  desc 'Prior to establishing a connection with another organization, a Memorandum of Understanding (MOU), Memorandum of Agreement (MOA), and/or Service Level Agreement (SLA) must be established between the two organizations.  This documentation, along with diagrams of the network topology, is required to be submitted to the DAAs for approval to connect to each other.  The policy must ensure that all connections to external networks conform equally.'
  desc 'check', "Verify Authorizing Official-approved MOAs, MOUs, and SLAs are up to date and included with the organization's accreditation package.  If the organization does not have MOAs, MOUs, and/or SLAs with the accreditation package, this is a finding."
  desc 'fix', 'Create MOUs, MOAs, and/or SLAs with other interconnected organizations, and then gain approval from the organization’s Authorizing Official and add the documentation to the accreditation package.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone C'
  tag check_id: 'C-46828r1_chk'
  tag severity: 'medium'
  tag gid: 'V-39673'
  tag rid: 'SV-51540r1_rule'
  tag stig_id: 'ENTD0340'
  tag gtitle: 'ENTD0340 - Approved contracts are not in place between interconnected organizations.'
  tag fix_id: 'F-44681r1_fix'
  tag 'documentable'
  tag ia_controls: 'DCID-1, EBCR-1, ECSC-1'
end
