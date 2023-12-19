control 'SV-84393' do
  title 'Exchange software must be installed on a separate partition from the OS.'
  desc 'In the same way that added security layers can provide a cumulative positive effect on security posture, multiple applications can provide a cumulative negative effect. A vulnerability and subsequent exploit to one application can lead to an exploit of other applications sharing the same security context. For example, an exploit to a web server process that leads to unauthorized administrative access to the host system can most likely lead to a compromise of all applications hosted by the same system.

Email services should be installed on a partition that does not host other applications. Email services should never be installed on a Domain Controller/Directory Services server.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine where the directory Exchange is installed.

Open Windows Explorer. 

Navigate to the directory or partition where Exchange is installed.

If Exchange resides on a directory or partition other than that of the OS and does not have other applications installed (unless approved by the ISSO), this is not a finding.'
  desc 'fix', 'Update the EDSP.

Install Exchange on a dedicated application directory or partition separate than that of the OS.'
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-70221r1_chk'
  tag severity: 'medium'
  tag gid: 'V-69771'
  tag rid: 'SV-84393r1_rule'
  tag stig_id: 'EX13-CA-000140'
  tag gtitle: 'SRG-APP-000431'
  tag fix_id: 'F-75983r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
