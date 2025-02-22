control 'SV-207367' do
  title 'The VMM must allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  desc "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the VMM's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify the VMM allows only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.

If it does not, this is a finding.'
  desc 'fix', 'Configure the VMM to allow only the ISSM (or individuals or roles appointed by the ISSM) to select which auditable events are to be audited.'
  impact 0.5
  ref 'DPMS Target Virtual Machine Manager'
  tag check_id: 'C-7624r365511_chk'
  tag severity: 'medium'
  tag gid: 'V-207367'
  tag rid: 'SV-207367r378724_rule'
  tag stig_id: 'SRG-OS-000063-VMM-000310'
  tag gtitle: 'SRG-OS-000063'
  tag fix_id: 'F-7624r365512_fix'
  tag 'documentable'
  tag legacy: ['V-56919', 'SV-71179']
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
end
