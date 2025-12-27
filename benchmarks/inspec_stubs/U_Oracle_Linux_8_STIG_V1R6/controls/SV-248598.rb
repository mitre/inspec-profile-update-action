control 'SV-248598' do
  title 'There must be no ".shosts" files on the OL 8 operating system.'
  desc 'The ".shosts" files are used to configure host-based authentication for individual users or the system via SSH. Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', %q(Verify there are no ".shosts" files on OL 8 with the following command: 
 
$ sudo find / -name '*.shosts' 
 
If any ".shosts" files are found, this is a finding.)
  desc 'fix', 'Remove any found ".shosts" files from the system. 
 
$ sudo rm /[path]/[to]/[file]/.shosts'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52032r779358_chk'
  tag severity: 'high'
  tag gid: 'V-248598'
  tag rid: 'SV-248598r779360_rule'
  tag stig_id: 'OL08-00-010470'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-51986r779359_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
