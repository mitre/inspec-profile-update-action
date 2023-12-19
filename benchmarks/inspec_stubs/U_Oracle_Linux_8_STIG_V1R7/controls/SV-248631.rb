control 'SV-248631' do
  title 'OL 8 must disable core dumps for all users.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors. 
 
A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers trying to debug problems.'
  desc 'check', %q(Verify the operating system disables core dumps for all users with the following command: 
 
$ sudo grep -r -s '^[^#].*core' /etc/security/limits.conf /etc/security/limits.d/*.conf 
 
* hard core 0 
 
This can be set as a global domain (with the * wildcard) but may be set differently for multiple domains. 
 
If the "core" item is missing or commented out or the value is anything other than "0", and the need for core dumps is not documented with the Information System Security Officer (ISSO) as an operational requirement for all domains that have the "core" item assigned, this is a finding.)
  desc 'fix', 'Configure OL 8 to disable core dumps for all users. 
 
Add the following line to the top of "/etc/security/limits.conf" or in a ".conf" file defined in "/etc/security/limits.d/": 
 
* hard core 0'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52065r779457_chk'
  tag severity: 'medium'
  tag gid: 'V-248631'
  tag rid: 'SV-248631r779459_rule'
  tag stig_id: 'OL08-00-010673'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-52019r779458_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
