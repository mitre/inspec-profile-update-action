control 'SV-87197' do
  title 'Bluetooth must be turned off unless approved by the organization.'
  desc 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system.  If a rogue device is paired with a system, there is potential for sensitive information to be compromised.'
  desc 'check', 'This is NA if the system does not have Bluetooth.

Verify the Bluetooth radio is turned off unless approved by the organization. If it is not, this is a finding.

Approval must be documented with the ISSO.'
  desc 'fix', 'Turn off Bluetooth radios not organizationally approved. Establish an organizational policy for the use of Bluetooth.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-72761r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36757'
  tag rid: 'SV-87197r1_rule'
  tag stig_id: 'WIN00-000210'
  tag gtitle: 'WN08-MO-000005'
  tag fix_id: 'F-78967r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
