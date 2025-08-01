control 'SV-220734' do
  title 'Bluetooth must be turned off unless approved by the organization.'
  desc 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system. If a rogue device is paired with a system, there is potential for sensitive information to be compromised.'
  desc 'check', 'This is NA if the system does not have Bluetooth.

Verify the Bluetooth radio is turned off unless approved by the organization. If it is not, this is a finding.

Approval must be documented with the ISSO.'
  desc 'fix', 'Turn off Bluetooth radios not organizationally approved. Establish an organizational policy for the use of Bluetooth.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 10'
  tag check_id: 'C-22449r554687_chk'
  tag severity: 'medium'
  tag gid: 'V-220734'
  tag rid: 'SV-220734r569187_rule'
  tag stig_id: 'WN10-00-000210'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-22438r554688_fix'
  tag 'documentable'
  tag legacy: ['SV-87403', 'V-72765']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
