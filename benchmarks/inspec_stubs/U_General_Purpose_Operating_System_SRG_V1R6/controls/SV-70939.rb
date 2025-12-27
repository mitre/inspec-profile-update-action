control 'SV-70939' do
  title 'The operating system must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify the operating system allows only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited. If it does not, this is a finding.'
  desc 'fix', 'Configure the operating system to allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  impact 0.5
  ref 'DPMS Target SRG-OS-GPOS'
  tag check_id: 'C-57249r1_chk'
  tag severity: 'medium'
  tag gid: 'V-56679'
  tag rid: 'SV-70939r1_rule'
  tag stig_id: 'SRG-OS-000063-GPOS-00032'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-61575r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
