control 'SV-48338' do
  title 'The location feature must be turned off.'
  desc 'The location service on mobile devices may allow sensitive data to be used by applications on the system.  This should be turned off unless explicitly allowed for approved systems/applications.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\LocationAndSensors\\

Value Name:  DisableLocation

Type:  REG_DWORD
Value:  1 (Enabled)

If location services are approved for the device by the organization, this may be set to "Disabled" (0).  This must be documented with the ISSO.'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Location and Sensors >> "Turn off location" to "Enabled".

If location services are approved by the organization for a device, this must be documented.'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45009r2_chk'
  tag severity: 'medium'
  tag gid: 'V-36708'
  tag rid: 'SV-48338r3_rule'
  tag stig_id: 'WN08-CC-000095'
  tag gtitle: 'WINCC-000095'
  tag fix_id: 'F-41470r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
