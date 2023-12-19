control 'SV-54070' do
  title 'Data used for testing and development must be downloaded through a secure connection to an IA-compliant system for vulnerability scanning prior to deployment in the test and development environment.'
  desc 'It is mandatory that data from an untrusted network or website that is to be used in a testing and development environment be downloaded through a secure perimeter.  Bringing data directly from an untrusted network or downloaded from a personal computer or home Internet connection must be prohibited.  Scanning data is crucial to ensure the integrity of the information prior to deployment for T&D processes.  While not an all-inclusive list, data in this situation includes OS patches, application updates, operating systems, development tools, and test data.  In the T&D environment, there will typically be one or more IA-compliant systems accessing a secure Internet connection. If a secure Internet connection is not available, such as in Zone D, a connection in another zone can be used and the data moved by approved physical media into the zone.  Scanning the data with an anti-virus program will reduce the risk of exploits and of having vulnerable systems in the T&D environment taken over.  Downloading data from a single workstation for all zone environments is acceptable.  Organizations with NIPRNet connections must download all data through their NIPR connection for scanning at the IAPs.  Contractors or other DoD organizations without any direct NIPRNet connectivity will need to use a secure Internet connection following all applicable DoD IA policy and STIG requirements.'
  desc 'check', '1. Verify an IA-compliant system has been deployed to scan downloaded data prior to deployment into the T&D environment.  Also, review the zone diagrams to ensure the workstation is documented appropriately.

2. Determine if the organization has a NIPRNet connection.
A. If the organization has a NIPRNet connection; data must be downloaded through the DoD IAP.

B. If the organization does not have a NIPRNet connection, data must be downloaded through a secure, IA-compliant connection.

If the organization does not download and scan the downloaded data to a dedicated IA-system and secure IA-compliant connection, this is a finding.'
  desc 'fix', '1. Deploy an IA-compliant system to download data.

2. Configure the IA-compliant system to download data through a secure, IA-compliant connection.
A. If your organization has a NIPRNet or connection; data must be downloaded through the DoD IAP.
  
B. If your organization does not have a NIPRNet or connection, data must be downloaded through a secure, IA-compliant connection.'
  impact 0.5
  ref 'DPMS Target Test Enclave - Zone A'
  tag check_id: 'C-48011r6_chk'
  tag severity: 'medium'
  tag gid: 'V-41494'
  tag rid: 'SV-54070r1_rule'
  tag stig_id: 'ENTD0360'
  tag gtitle: 'ENTD0360 - Test and development data not securely downloaded.'
  tag fix_id: 'F-46950r4_fix'
  tag 'documentable'
end
