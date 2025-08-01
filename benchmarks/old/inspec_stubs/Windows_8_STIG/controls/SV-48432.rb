control 'SV-48432' do
  title 'Bluetooth must be turned off unless approved by the organization.'
  desc 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system.  If a rogue device is paired with a system, there is potential for sensitive information to be compromised.  DoD policy and Wireless STIG guidance must be implemented with the use of Bluetooth.'
  desc 'check', 'Verify the Bluetooth radio is turned off unless approved by the organization.  If it is not, this is a finding.

Approval must be documented with the ISSO.

If the system does not have Bluetooth, this is not applicable.'
  desc 'fix', 'Turn off Bluetooth radios not organizationally approved.  Establish an organizational policy for the use of Bluetooth.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45101r2_chk'
  tag severity: 'medium'
  tag gid: 'V-36757'
  tag rid: 'SV-48432r3_rule'
  tag stig_id: 'WN08-MO-000005'
  tag gtitle: 'WN08-MO-000005'
  tag fix_id: 'F-41563r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
