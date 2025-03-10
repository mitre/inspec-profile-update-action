control 'SV-48243' do
  title 'Errors in handwriting recognition on tablet PCs must not be reported to Microsoft.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents errors in handwriting recognition on tablet PCs from being reported to Microsoft.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\HandwritingErrorReports\\

Value Name: PreventHandwritingErrorReports

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off handwriting recognition error reporting" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44922r1_chk'
  tag severity: 'low'
  tag gid: 'V-15704'
  tag rid: 'SV-48243r2_rule'
  tag stig_id: 'WN08-CC-000035'
  tag gtitle: 'Handwriting Recognition Error Reporting'
  tag fix_id: 'F-41379r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
