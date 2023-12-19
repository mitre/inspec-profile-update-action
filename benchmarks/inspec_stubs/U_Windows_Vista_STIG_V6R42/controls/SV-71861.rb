control 'SV-71861' do
  title 'The system must be configured to store error reports locally, on the system or in the enclave, and not send them to Microsoft.'
  desc "Forwarding error reports to vendors could expose sensitive information.  This setting controls the configuration of a local or DOD-wide error reporting site.   In order to not send the data to any system at this time, yet create the reports locally on the system, this value needs to be a single blank character.  To forward error reports to a collection server, the site's error reporting server name or IP address must be defined."
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\

Value Name:  CorporateWerServer

Type:  REG_SZ
Value:  " "       (A single BLANK character to store the data on the system or the error reporting server name or IP address to forward the data to.)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> Advanced Error Reporting Settings -> "Configure Corporate Windows Error Reporting" -> to "Enabled" with "Corporate server name:" defined as a single blank character to store the data on the system or the name or IP address of the local collection server.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-58299r1_chk'
  tag severity: 'medium'
  tag gid: 'V-57457'
  tag rid: 'SV-71861r1_rule'
  tag stig_id: 'WINER-000007'
  tag gtitle: 'WINER-000007'
  tag fix_id: 'F-62659r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
