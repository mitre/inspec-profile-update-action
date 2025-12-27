control 'SV-48435' do
  title 'Bluetooth must be turned off when not in use.'
  desc 'If not configured properly, Bluetooth may allow rogue devices to communicate with a system.  If a rogue device is paired with a system, there is potential for sensitive information to be compromised.'
  desc 'check', 'Verify the organization has a policy to turn off Bluetooth when not in use and personnel are trained.  If it does not, this is a finding.

If the system does not have Bluetooth or it is disabled, this is not applicable.'
  desc 'fix', 'Turn off Bluetooth radios when not in use.  Establish an organizational policy for the use of Bluetooth to include training of personnel.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45102r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36759'
  tag rid: 'SV-48435r2_rule'
  tag stig_id: 'WN08-MO-000006'
  tag gtitle: 'WN08-MO-000006'
  tag fix_id: 'F-41564r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECWN-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
