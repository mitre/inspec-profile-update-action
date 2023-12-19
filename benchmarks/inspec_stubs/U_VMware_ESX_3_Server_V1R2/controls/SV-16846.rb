control 'SV-16846' do
  title 'Production virtual machines are not located in a controlled access area.'
  desc 'Virtual machines may contain an aggregate of sensitive and non-sensitive data.  If this data is not located in a controlled access area, unauthorized users may gain access to the virtual machines and have access to the data. This access may result in the loss of privacy and data theft.'
  desc 'check', 'Review the location of the virtual machines.  Ensure that authorized users are required to verify their identity and authority before gaining access to the virtual machines. If the virtual machines are not located in a controlled access area, this is a finding.'
  desc 'fix', 'Place all virtual machines in a controlled access area.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16264r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15904'
  tag rid: 'SV-16846r1_rule'
  tag stig_id: 'ESX1080'
  tag gtitle: 'Production virtual machines not in controlled area'
  tag fix_id: 'F-15865r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
end
