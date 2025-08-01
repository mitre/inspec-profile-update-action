control 'SV-254177' do
  title 'Nutanix AOS must produce audit records containing the individual identities of group account users.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the individual identities of group users. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the actual account involved in the activity.'
  desc 'check', 'Verify Nutanix AOS produces audit records containing information to establish when (date and time) the events occurred.

Determine if auditing is active by issuing the following command:

$ sudo systemctl is-active auditd.service
active

If the "auditd" status is not active, this is a finding.'
  desc 'fix', 'Enable the auditd service to run automatically.

$ sudo systemctl enable auditd'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57662r846617_chk'
  tag severity: 'medium'
  tag gid: 'V-254177'
  tag rid: 'SV-254177r846619_rule'
  tag stig_id: 'NUTX-OS-000750'
  tag gtitle: 'SRG-OS-000042-GPOS-00021'
  tag fix_id: 'F-57613r846618_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
