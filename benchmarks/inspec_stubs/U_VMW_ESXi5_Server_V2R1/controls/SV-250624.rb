control 'SV-250624' do
  title 'System BIOS or system controllers supporting password protection must have administrator accounts/passwords configured, and no others.'
  desc "A system's BIOS or system controller handles the initial startup of a system and its configuration must be protected from unauthorized modification. When the BIOS or system controller supports the creation of user accounts or passwords, such protections must be used and accounts/passwords only assigned to system administrators. Failure to protect BIOS or system controller settings could result in Denial-of-Service or compromise of the system resulting from unauthorized configuration changes."
  desc 'check', 'On systems with a BIOS or system controller, ask the SA if a supervisor or administrator password is set. If a password is not set, this is a finding.'
  desc 'fix', 'On systems with a BIOS or system controller, set the supervisor or administrator password.'
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54059r798869_chk'
  tag severity: 'medium'
  tag gid: 'V-250624'
  tag rid: 'SV-250624r798871_rule'
  tag stig_id: 'SRG-OS-000080-ESXI5'
  tag gtitle: 'SRG-OS-000080-VMM-000470'
  tag fix_id: 'F-54013r798870_fix'
  tag 'documentable'
  tag legacy: ['SV-51080', 'V-39264']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
