control 'SV-203620' do
  title 'The operating system must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify the operating system allows only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  impact 0.5
  ref 'DPMS Target General Purpose Operating System'
  tag check_id: 'C-3745r557584_chk'
  tag severity: 'medium'
  tag gid: 'V-203620'
  tag rid: 'SV-203620r557586_rule'
  tag stig_id: 'SRG-OS-000063-GPOS-00032'
  tag gtitle: 'SRG-OS-000063'
  tag fix_id: 'F-3745r557585_fix'
  tag 'documentable'
  tag legacy: ['V-56679', 'SV-70939']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
