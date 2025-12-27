control 'SV-17881' do
  title 'Permissions on the virtual disk files are incorrect.'
  desc 'Permissions for the virtual machine files will adhere to VMware’s best practices. The configuration file (.vmx), will be read, write, execute (rwx) for owner and read and execute (r-x) for group and read (r--) for others (754). The virtual machine’s virtual disk (.vmdk) will be read and write (rw-) for owner (600).'
  desc 'check', 'On the ESX Server host, perform the following commands on the service console:
	
# find /vmfs or nfs –type f –name ‘*.vmdk’ –exec ls –Al {} \\; | grep –v -- “rw--------“

Any result from this command is a finding.  If no result is returned, this is not a finding.
Permissions for all .vmdk files should be 600 or rw-------.  If they are not, this is a finding.'
  desc 'fix', 'Configure .vmdk files to 600.'
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-17470r1_chk'
  tag severity: 'medium'
  tag gid: 'V-16881'
  tag rid: 'SV-17881r1_rule'
  tag stig_id: 'ESX0055'
  tag gtitle: 'Incorrect permissions on virtual disk files'
  tag fix_id: 'F-16730r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
  tag ia_controls: 'ECSC-1'
end
