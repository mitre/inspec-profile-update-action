control 'SV-214878' do
  title 'The macOS system must implement NSA-approved cryptography to protect classified information in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.'
  desc 'Use of weak or untested encryption algorithms undermines the purposes of using encryption to protect data. The operating system must implement cryptographic modules adhering to the higher standards approved by the federal government since this provides assurance they have been tested and validated.

'
  desc 'check', 'To check which protocol is configured for sshd, run the following:

/usr/bin/sudo /usr/bin/grep ^Protocol /etc/ssh/sshd_config

If there is no result or the result is not "Protocol 2", this is a finding.'
  desc 'fix', %q(To ensure that "Protocol 2" is used by sshd, run the following command:

/usr/bin/sudo /usr/bin/sed -i.bak 's/.*Protocol.*/Protocol 2/' /etc/ssh/sshd_config)
  impact 0.5
  ref 'DPMS Target Apple OS X 10.13'
  tag check_id: 'C-16078r397206_chk'
  tag severity: 'medium'
  tag gid: 'V-214878'
  tag rid: 'SV-214878r609363_rule'
  tag stig_id: 'AOSX-13-000570'
  tag gtitle: 'SRG-OS-000112-GPOS-00057'
  tag fix_id: 'F-16076r397207_fix'
  tag satisfies: ['SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058', 'SRG-OS-000396-GPOS-00176']
  tag 'documentable'
  tag legacy: ['V-81635', 'SV-96349']
  tag cci: ['CCI-001941', 'CCI-001942', 'CCI-002450']
  tag nist: ['IA-2 (8)', 'IA-2 (9)', 'SC-13 b']
end
