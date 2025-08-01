control 'SV-16843' do
  title 'Virtual machine moves are not logged from one physical server to another.'
  desc 'Virtual machines may be moved from one computer to another similar to a normal file. This portability gives rise to a host of security problems.  In the virtual machine world, the trusted computing base consists of all the hosts that the virtual machine has run on.  If no history was maintained for each virtual machine, this can make it very difficult to figure out how far a security compromise has extended if the virtual machine has been moved several times.'
  desc 'check', 'Ask the IAO/SA if Vmotion is used to migrate virtual machines from one ESX Server host to another.  If not, this is Not Applicable.  If so, perform the following on the ESX Server service console:

# grep –in vmotion /var/log/vmware/vpx/vpxa*.log

If the logs are compressed, perform the following:

# zcat /var/log/vmware/vpx/vpxa*.log.gz | grep –i vmotion 
 
If no result is returned, this is a finding.'
  desc 'fix', 'Log all VMotion migrations.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16261r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15901'
  tag rid: 'SV-16843r1_rule'
  tag stig_id: 'ESX1050'
  tag gtitle: 'Virtual machine moves are not logged'
  tag fix_id: 'F-15862r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECAR-1, ECAR-2, ECAR-3'
end
