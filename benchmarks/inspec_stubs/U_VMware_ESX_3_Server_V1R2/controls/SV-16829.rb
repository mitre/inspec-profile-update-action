control 'SV-16829' do
  title 'Master templates are not restricted to authorized users only.'
  desc 'Restricting access to master templates to authorized users helps ensure they are not compromised or modified. If these master templates were compromised, all future guest installations could be corrupt or contain malicious code.  Master templates will be restricted to only users that are administering and/or creating guest virtual machines.'
  desc 'check', 'On the ESX Server service console perform the following command to determine if the /Master, /Utilities, or /vmimages file partitions are accessible to unauthorized users.

# ls -la /vmimages (Or name of master template directory)
 
Permissions for .vmdk files should be 600 or rw-------. If they are not 600 or more restrictive, this is a finding.'
  desc 'fix', 'Restrict master templates to authorized users only.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-16247r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15888'
  tag rid: 'SV-16829r1_rule'
  tag stig_id: 'ESX0920'
  tag gtitle: 'Master templates are not restricted'
  tag fix_id: 'F-15848r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Machine Administrator]']
  tag ia_controls: 'ECAN-1, ECCD-1, ECCD-2'
end
