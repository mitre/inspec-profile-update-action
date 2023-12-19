control 'SV-44045' do
  title 'Email application must not share a partition with another application.'
  desc 'In the same way that added security layers can provide a cumulative positive effect on security posture, multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to the host system can most likely lead to a compromise of all applications hosted by the same system.

Email services should be installed on a partition that does not host other applications. Email services should never be installed on a Domain Controller / Directory Services server.'
  desc 'check', 'Access Windows Explorer and identify the OS partition. Navigate to configured partitions, and access the ‘Program Files’ directory. 

Make note of the installation partition for Microsoft Exchange. 

If Microsoft Exchange resides on a partition other than that of the OS, and does not have other applications installed, this is not a finding.
Note: In the case where additional applications are installed on the same partition as Microsoft Exchange, and each of those additional applications have been documented and had a risk assessment completed by the ISSO/ISSM, this is not a finding.'
  desc 'fix', 'Install Exchange on a dedicated application partition separate than that of the OS.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41732r3_chk'
  tag severity: 'medium'
  tag gid: 'V-33625'
  tag rid: 'SV-44045r3_rule'
  tag stig_id: 'Exch-3-807'
  tag gtitle: 'Exch-3-807'
  tag fix_id: 'F-37517r1_fix'
  tag 'documentable'
end
