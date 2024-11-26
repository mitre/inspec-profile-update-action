control 'SV-68609' do
  title 'The ALG providing intermediary services for remote access communications traffic must provide the capability to immediately disconnect or disable remote access to the information system.'
  desc 'Without the ability to immediately disconnect or disable remote access, an attack or other compromise taking progress would not be immediately stopped.

Remote access functionality must have the capability to immediately disconnect current users remotely accessing the information system and/or disable further remote access. The remote access functionality may implement features, such as automatic disconnect (or user-initiated disconnect) in case of adverse information based on an indicator of compromise or attack.

This requirement applies to ALGs providing remote access termination (e.g., OWA or TLS gateway) as part of its intermediary services.'
  desc 'check', 'If the ALG does not serve as an intermediary for remote access traffic (e.g., web content filter, TLS and webmail), this is not applicable.

Verify the ALG provides the capability to immediately disconnect or disable remote access to the information system.

If the ALG does not provide the capability to immediately disconnect or disable remote access to the information system, this is a finding.'
  desc 'fix', 'If intermediary services for remote access communications traffic are provided, configure the ALG to provide the capability to immediately disconnect or disable remote access to the information system.'
  impact 0.5
  ref 'DPMS Target SRG-NET-ALG'
  tag check_id: 'C-54979r1_chk'
  tag severity: 'medium'
  tag gid: 'V-54363'
  tag rid: 'SV-68609r1_rule'
  tag stig_id: 'SRG-NET-000314-ALG-000013'
  tag gtitle: 'SRG-NET-000314-ALG-000013'
  tag fix_id: 'F-59217r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
