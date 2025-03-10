control 'SV-26255' do
  title 'The system must have IEEE 1394 (Firewire) disabled unless needed.'
  desc 'Firewire is a common computer peripheral interface. Firewire devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', 'If the system needs IEEE 1394, this is not applicable.

Determine if IEEE 1394 is enabled on the system. If so, this is a finding.'
  desc 'fix', 'Disable IEEE 1394 on the system.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29141r1_chk'
  tag severity: 'low'
  tag gid: 'V-22580'
  tag rid: 'SV-26255r1_rule'
  tag stig_id: 'GEN008500'
  tag gtitle: 'GEN008500'
  tag fix_id: 'F-26148r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
