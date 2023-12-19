control 'SV-248633' do
  title 'OL 8 must disable core dump backtraces.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors. 
 
A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.'
  desc 'check', 'Verify the operating system disables core dump backtraces by issuing the following command: 
 
$ sudo grep -i ProcessSizeMax /etc/systemd/coredump.conf 
 
ProcessSizeMax=0 
 
If the "ProcessSizeMax" item is missing or commented out or the value is anything other than "0", and the need for core dumps is not documented with the Information System Security Officer (ISSO) as an operational requirement for all domains that have the "core" item assigned, this is a finding.'
  desc 'fix', 'Configure OL 8 to disable core dump backtraces. 
 
Add or modify the following line in "/etc/systemd/coredump.conf": 
 
ProcessSizeMax=0'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52067r779463_chk'
  tag severity: 'medium'
  tag gid: 'V-248633'
  tag rid: 'SV-248633r779465_rule'
  tag stig_id: 'OL08-00-010675'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52021r779464_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
