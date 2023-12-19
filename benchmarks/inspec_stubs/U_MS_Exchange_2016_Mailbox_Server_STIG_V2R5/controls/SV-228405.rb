control 'SV-228405' do
  title 'The Exchange Email application must not share a partition with another application.'
  desc 'In the same way that added security layers can provide a cumulative positive effect on security posture, multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to the host system can most likely lead to a compromise of all applications hosted by the same system.

Email services should be installed on a partition that does not host other applications. Email services should never be installed on a Domain Controller/Directory Services server.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine if the directory Exchange is installed.

Open Windows Explorer.

Navigate to where Exchange is installed. 

If Exchange resides on a directory or partition other than that of the operating system and does not have other applications installed (unless approved by the Information System Security Officer [ISSO]), this is not a finding.'
  desc 'fix', 'Update the EDSP with the location of where Exchange is installed.

Install Exchange on a dedicated application directory or partition separate than that of the operating system.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30638r497011_chk'
  tag severity: 'medium'
  tag gid: 'V-228405'
  tag rid: 'SV-228405r879802_rule'
  tag stig_id: 'EX16-MB-000620'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-30623r497012_fix'
  tag 'documentable'
  tag legacy: ['SV-95447', 'V-80737']
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
