control 'SV-69015' do
  title 'The ALG providing user access control intermediary services must provide the capability for authorized users to capture, record, and log all content related to a selected user session.'
  desc 'Without the capability to capture, record, and log content related to a user session, investigations into suspicious user activity would be hampered.

The intent of this requirement is to ensure the capability to select specific sessions to capture is available in order to support general auditing/incident investigation, or to validate suspected misuse by a specific user. Examples of session events that may be captured include, port mirroring, tracking websites visited, and recording information and/or file transfers.'
  desc 'check', 'If the ALG does not provide user access control and intermediary services, this is not applicable.

Verify the ALG provides the capability for authorized users to capture, record, and log all content related to a user session.

If the ALG does not provide the capability for authorized users to capture, record, and log all content related to a user session, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to provide the capability for authorized users to capture, record, and log all content related to a user session.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55391r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54769'
  tag rid: 'SV-69015r1_rule'
  tag stig_id: 'SRG-NET-000399-ALG-000042'
  tag gtitle: 'SRG-NET-000399-ALG-000042'
  tag fix_id: 'F-59627r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001462']
  tag nist: ['AU-14 (2)']
end
