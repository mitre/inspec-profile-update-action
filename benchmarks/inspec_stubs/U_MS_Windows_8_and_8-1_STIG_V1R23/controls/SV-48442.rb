control 'SV-48442' do
  title 'Built-in microphones must be disabled on mobile devices unless required and approved by the organization.'
  desc 'Microphones can capture audio of sensitive information.  There is also a potential for remote access, and microphones must be turned off unless approved by local policy.'
  desc 'check', 'Verify microphones are turned off unless approved by the organization.   View status in device manager.
If built-in microphones are not approved by local policy or disabled, this is a finding.

If the system does not have built-in microphones, this is not applicable.'
  desc 'fix', 'Disable microphones in device manager if not organizationally approved.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45106r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36765'
  tag rid: 'SV-48442r2_rule'
  tag stig_id: 'WN08-MO-000010'
  tag gtitle: 'WN08-MO-000010'
  tag fix_id: 'F-41569r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
