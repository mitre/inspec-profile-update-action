control 'SV-16726' do
  title 'Permissions on the configuration and virtual disk files are incorrect.'
  desc 'Permissions for the virtual machine files will adhere to VMware’s best practices. The configuration file (.vmx), will be read, write, execute (rwx) for owner and read and execute (r-x) for group and read (r--) for others (754). The virtual machine’s virtual disk (.vmdk) will be read and write (rw-) for owner (600).'
  desc 'check', 'On the ESX Server host, perform the following commands on the service console:
	
# find /vmfs or nfs –type f –name ‘*.vmx’ –exec ls –Al {} \\; | grep –v -- “rwxr-x-r--“

Review the results from this command.  If the result has permissions that are more restrictive, then this is not a finding.  Any result that has less restrictive permissions (greater than 754) is a finding. If no result is returned, then this is not a finding. Permissions for all .vmx files should be 754 or rwxr-xr—or more restrictive.'
  desc 'fix', 'Configure .vmx files to 754.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-15973r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15787'
  tag rid: 'SV-16726r1_rule'
  tag stig_id: 'ESX0050'
  tag gtitle: 'Virtual disk files permissions are incorrect.'
  tag fix_id: 'F-15728r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECSC-1'
end
