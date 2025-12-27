control 'SV-68737' do
  title 'The ALG that is part of a CDS must block the transfer of data with malformed security attribute metadata structures.'
  desc 'Enforcing allowed information flows based on metadata enables simpler and more effective flow control. Metadata is information used to describe the characteristics of data. Metadata can include structural metadata describing data structures (e.g., data format, syntax, and semantics) or descriptive metadata describing data contents (e.g., age, location, telephone number).

For cross domain solutions, security attributes are defined as, at a minimum, source and destination address.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG is configured to block the transfer of data with malformed security attribute metadata structures.

If the ALG is not configured to block the transfer of data with malformed security attribute metadata structures, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to block the transfer of data with malformed security attribute metadata structures.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55107r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54491'
  tag rid: 'SV-68737r1_rule'
  tag stig_id: 'SRG-NET-000280-ALG-000081'
  tag gtitle: 'SRG-NET-000280-ALG-000081'
  tag fix_id: 'F-59345r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000030', 'CCI-000366']
  tag nist: ['AC-4 (6)', 'CM-6 b']
end
