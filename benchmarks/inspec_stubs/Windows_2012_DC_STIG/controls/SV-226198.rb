control 'SV-226198' do
  title 'The location feature must be turned off.'
  desc 'The location service on systems may allow sensitive data to be used by applications on the system.  This should be turned off unless explicitly allowed for approved systems/applications.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\LocationAndSensors\\

Value Name: DisableLocation

Type: REG_DWORD
Value: 1 (Enabled)

If location services are approved for the system by the organization, this may be set to "Disabled" (0).  This must be documented with the ISSO.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Location and Sensors -> "Turn off location" to "Enabled".

If location services are approved by the organization for a device, this must be documented.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27900r475917_chk'
  tag severity: 'medium'
  tag gid: 'V-226198'
  tag rid: 'SV-226198r794441_rule'
  tag stig_id: 'WN12-CC-000095'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27888r475918_fix'
  tag 'documentable'
  tag legacy: ['SV-51748', 'V-36708']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
