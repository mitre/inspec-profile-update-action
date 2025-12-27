control 'SV-84549' do
  title 'Exchange must provide redundancy.'
  desc 'Denial of Service (DoS) is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of applications to mitigate the impact of DoS attacks that have occurred or are ongoing on application availability. For each application, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the application opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine if the Exchange servers are using redundancy by entering the following command:

Get-TransportService | select FL 

If the value returned is not at least two Edge servers, this is a finding.

Note: The EDSP must indicate what availability the system must have, as approved by the ISSO. This will be used for finding and severity downgrade purposes in other requirements.'
  desc 'fix', 'Update the EDSP.

Configure two or more Edge servers for load balancing.'
  impact 0.7
  ref 'DPMS Target Microsoft Exchange 2013 Edge Transport Server'
  tag check_id: 'C-70397r2_chk'
  tag severity: 'high'
  tag gid: 'V-69927'
  tag rid: 'SV-84549r2_rule'
  tag stig_id: 'EX13-EG-000330'
  tag gtitle: 'SRG-APP-000435'
  tag fix_id: 'F-76159r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002418']
  tag nist: ['SC-8']
end
