control 'SV-69013' do
  title 'The ALG providing user access control intermediary services must provide the capability for authorized users to select a user session to capture or view.'
  desc 'Without the capability to select a user session to capture or view, investigations into suspicious or harmful events would be hampered by the volume of information captured.

The intent of this requirement is to ensure the capability to select specific sessions to capture is available in order to support general auditing/incident investigation, or to validate suspected misuse by a specific user. Examples of session events that may be captured include, port mirroring, tracking websites visited, and recording information and/or file transfers.'
  desc 'check', 'If the ALG does not provide user access control intermediary services, this is not applicable.

Verify the ALG provides the capability for authorized users to select a user session to capture or view.

If the ALG does not provide the capability for authorized users to select a user session to capture or view, this is a finding.'
  desc 'fix', 'If user access control intermediary services are provided, configure the ALG to provide the capability for authorized users to select a user session to capture or view.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-55389r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54767'
  tag rid: 'SV-69013r1_rule'
  tag stig_id: 'SRG-NET-000331-ALG-000041'
  tag gtitle: 'SRG-NET-000331-ALG-000041'
  tag fix_id: 'F-59625r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001919']
  tag nist: ['AU-14 a']
end
