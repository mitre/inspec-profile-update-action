control 'SV-16740' do
  title 'The ESX Server does not meet the minimum requirement of two network adapters.'
  desc 'A minimum of two physical network adapters is required in each physical server to enable networking for both the service console and the virtual machines.  A minimum of two network adapters per ESX Server are required because the first network adapter discovered during the installation of the ESX Server is always dedicated to the service console by default. Up to 16 physical network adapters are supported per ESX Server. The ESX Server service console network adapter connects to the management user interface, SCP, SSH, and any other tool used to access the ESX Server’s file system. The other physical network adapter will be dedicated to the virtual machines'
  desc 'check', 'Go to the ESX Server service console, and type the following:
# esxcfg-nics –l
vmnic0
vmnic1

If you do not see vmnic0 and vmnic1 in the listing, this is a finding.  A minimum of two network adapters are required.'
  desc 'fix', 'Configure the ESX Server with two network adapters.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16014r1_chk'
  tag severity: 'low'
  tag gid: 'V-15801'
  tag rid: 'SV-16740r1_rule'
  tag stig_id: 'ESX0120'
  tag gtitle: 'ESX Server does not have two NICs.'
  tag fix_id: 'F-15744r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
