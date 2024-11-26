control 'SV-234258' do
  title 'The application must be configured to disable non-essential capabilities.'
  desc 'It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors.

Applications are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

Examples of non-essential capabilities include, but are not limited to, advertising software or browser plug-ins not related to requirements or providing a wide array of functionality not required for every mission but cannot be disabled.'
  desc 'check', 'Run the following command on a client to disable the CEIP:
/opt/Citrix/VDA/bin/ctxreg update -k "HKEY_LOCAL_MACHINE\\ SOFTWARE\\Citrix\\CEIP" -v "CEIPSwitch" -d "1"

If CEIPSwitch is not set to "1", this is a finding.

Run the following command on a client to disable Google Analytics:
/opt/Citrix/VDA/bin/ctxreg update -k "HKEY_LOCAL_MACHINE\\ SOFTWARE\\Citrix\\CEIP" -v "GASwitch" -d "1"

If GASwitch is not set to "1", this is a finding.'
  desc 'fix', 'Set the value of CEIPSwitch to "1" (Disabled).

Set the value of GASwitch to "1" (Disabled).'
  impact 0.5
  ref 'DPMS Target Citrix VAD 7.x LVDA'
  tag check_id: 'C-37443r612328_chk'
  tag severity: 'medium'
  tag gid: 'V-234258'
  tag rid: 'SV-234258r628796_rule'
  tag stig_id: 'LVDA-VD-000270'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-37408r612329_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
