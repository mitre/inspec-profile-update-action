control 'SV-206524' do
  title 'The DBMS must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent or interfere with the auditing of critical events.

Suppression of auditing could permit an adversary to evade detection.

Misconfigured audits can degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Check DBMS settings and documentation to determine whether designated personnel are able to select which auditable events are being audited.

If designated personnel are not able to configure auditable events, this is a finding.'
  desc 'fix', "Configure the DBMS's settings to allow designated personnel to select which auditable events are audited."
  impact 0.5
  ref 'DPMS Target Database Generic'
  tag check_id: 'C-6784r291240_chk'
  tag severity: 'medium'
  tag gid: 'V-206524'
  tag rid: 'SV-206524r617447_rule'
  tag stig_id: 'SRG-APP-000090-DB-000065'
  tag gtitle: 'SRG-APP-000090'
  tag fix_id: 'F-6784r291241_fix'
  tag 'documentable'
  tag legacy: ['SV-42700', 'V-32363']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
