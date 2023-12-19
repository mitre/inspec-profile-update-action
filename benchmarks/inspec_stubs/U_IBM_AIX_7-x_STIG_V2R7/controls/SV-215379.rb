control 'SV-215379' do
  title 'The pcnfsd daemon must be disabled on AIX.'
  desc "The pcnfsd service is an authentication and printing program, which uses NFS to provide file transfer services. This service is vulnerable and exploitable and permits the machine to be compromised both locally and remotely. If PC NFS clients are required within the environment, Samba is recommended as an alternative software solution. The pcnfsd daemon predates Microsoft's release of SMB specifications. This service should therefore be disabled to prevent attacks."
  desc 'check', 'From the command prompt, execute the following command: 
# grep "^pcnfsd[[:blank:]]" /etc/inetd.conf

If there is any output from the command, this is a finding.'
  desc 'fix', %q(In "/etc/inetd.conf", comment out the "pcnfsd" entry by running command: 
# chsubserver -r inetd -C /etc/inetd.conf -d -v 'pcnfsd' -p 'udp'

Restart inetd:
# refresh -s inetd)
  impact 0.5
  ref 'DPMS Target IBM AIX 7.x'
  tag check_id: 'C-16577r294588_chk'
  tag severity: 'medium'
  tag gid: 'V-215379'
  tag rid: 'SV-215379r508663_rule'
  tag stig_id: 'AIX7-00-003074'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-16575r294589_fix'
  tag 'documentable'
  tag legacy: ['SV-101485', 'V-91387']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
