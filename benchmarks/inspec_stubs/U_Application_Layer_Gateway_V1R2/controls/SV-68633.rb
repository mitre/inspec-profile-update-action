control 'SV-68633' do
  title 'The ALG that is part of a CDS must apply information flow control to data transferred between security domains by means of a policy filter which consists of a set of hardware and/or software.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data.

Apply information flow control to data transferred between security domains by means of a set of hardware and/or software, collectively known as the "filter". Flow control includes the inspection, sanitization, and/or rejection of data from one security domain prior to transfer of data to a different security domain. For an access type CDS, the remote desktop architecture provides the capability for a user to have access from a single device to computing platforms, applications, or data residing on multiple different security domains; while preventing any information flow between the different security domains.'
  desc 'check', 'If the ALG is not used as part of a CDS, this is not applicable.

Verify the ALG applies information flow control to data transferred between security domains by means of a policy filter which consists of a set of hardware and/or software.

If the ALG is not configured to apply information flow control to data transferred between security domains by means of a policy filter which consists of a set of hardware and/or software, this is a finding.'
  desc 'fix', 'If the ALG is used as part of a CDS, configure the ALG to apply information flow control to data transferred between security domains by means of a policy filter which consists of a set of hardware and/or software.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55003r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54387'
  tag rid: 'SV-68633r1_rule'
  tag stig_id: 'SRG-NET-000019-ALG-000021'
  tag gtitle: 'SRG-NET-000019-ALG-000021'
  tag fix_id: 'F-59241r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
