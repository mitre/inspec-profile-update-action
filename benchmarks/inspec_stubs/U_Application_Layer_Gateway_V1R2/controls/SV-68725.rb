control 'SV-68725' do
  title 'The ALG that is part of a CDS must uniquely identify and authenticate source by organization, system, application, and/or individual for information transfer.'
  desc 'Attribution is a critical component of a security concept of operations. The ability to identify source and destination points for information flowing in information systems, allows the forensic reconstruction of events when required, and encourages policy compliance by attributing policy violations to specific organizations/individuals. Successful domain authentication requires that information system labels distinguish among systems, organizations, and individuals involved in preparing, sending, receiving, or disseminating information.'
  desc 'check', 'If the ALG is not part of a CDS, this is not applicable.

Verify the ALG uniquely identifies and authenticates source by organization, system, application, and/or individual for information transfer.

If the ALG is not configured to uniquely identify and authenticate source by organization, system, application, and/or individual for information transfer, this is a finding.'
  desc 'fix', 'If the ALG is part of a CDS, configure the ALG to uniquely identify and authenticate source by organization, system, application, and/or individual for information transfer.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55095r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54479'
  tag rid: 'SV-68725r1_rule'
  tag stig_id: 'SRG-NET-000325-ALG-000075'
  tag gtitle: 'SRG-NET-000325-ALG-000075'
  tag fix_id: 'F-59333r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
