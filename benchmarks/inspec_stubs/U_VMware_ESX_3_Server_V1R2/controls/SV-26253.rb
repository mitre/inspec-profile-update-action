control 'SV-26253' do
  title 'The system must have USB disabled unless needed.'
  desc 'USB is a common computer peripheral interface. USB devices may include storage devices that could be used to install malicious software on a system or exfiltrate data.'
  desc 'check', 'If the system uses USB, this is not applicable.

Determine if the system has USB enabled. If it does, this is a finding.'
  desc 'fix', 'Disable USB on the system.'
  impact 0.3
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29139r1_chk'
  tag severity: 'low'
  tag gid: 'V-22578'
  tag rid: 'SV-26253r1_rule'
  tag stig_id: 'GEN008460'
  tag gtitle: 'GEN008460'
  tag fix_id: 'F-26146r1_fix'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
