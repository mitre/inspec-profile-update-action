control 'SV-69575' do
  title 'The IDPS must assign a critical severity level to all audit processing failures.'
  desc 'It is critical that when the IDPS is at risk of failing to process audit logs as required, it takes action to mitigate the failure

Audit processing failures include: software/hardware errors; failures in the audit capturing mechanisms; and audit storage capacity being reached or exceeded. Since action must be taken immediately, these messages will be designated as a critical severity level and this level must be sent as part of the alert message.'
  desc 'check', 'Verify the IDPS provides assign a critical severity level to all audit processing failures.

If the IDPS does not assign a critical severity level to all audit processing failures, this is a finding.'
  desc 'fix', 'Configure the IDPS to assign a critical severity level to all audit processing failures.'
  impact 0.5
  ref 'DPMS Target SRG-NET-IDPS'
  tag check_id: 'C-55951r1_chk'
  tag severity: 'medium'
  tag gid: 'V-55329'
  tag rid: 'SV-69575r1_rule'
  tag stig_id: 'SRG-NET-000335-IDPS-00223'
  tag gtitle: 'SRG-NET-000335-IDPS-00223'
  tag fix_id: 'F-60195r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001858']
  tag nist: ['AU-5 (2)']
end
