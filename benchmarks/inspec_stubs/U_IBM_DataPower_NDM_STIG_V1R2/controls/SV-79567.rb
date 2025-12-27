control 'SV-79567' do
  title 'The DataPower Gateway must protect audit tools from unauthorized access.'
  desc 'Protecting audit data also includes identifying and protecting the tools used to view and manipulate log data. Therefore, protecting audit tools is necessary to prevent unauthorized operation on audit data.

Network devices providing tools to interface with audit data will leverage user permissions and roles identifying the user accessing the tools and the corresponding rights the user enjoys in order to make access decisions regarding the access to audit tools.

Audit tools include, but are not limited to, vendor-provided and open source audit tools needed to successfully view and manipulate audit information system activity and records. Audit tools include custom queries and report generators.'
  desc 'check', 'Logon page >> Enter non-admin user ID and password, select Default for domain >> Click "Login". If non-admin user can log on, this is a finding.'
  desc 'fix', 'Privileged account user log on to default domain >> Administration >> Access >> User Account >> Select non-privileged user account >> Click “…” button next to User Group field >> Enter */default/*?Access=NONE into field >> Click "Add" >> Click "Apply" >> Click "Apply" >> Click "Save Configuration".'
  impact 0.5
  ref 'DPMS Target IBM DataPower XI52 NDM'
  tag check_id: 'C-65703r1_chk'
  tag severity: 'medium'
  tag gid: 'V-65077'
  tag rid: 'SV-79567r1_rule'
  tag stig_id: 'WSDP-NM-000039'
  tag gtitle: 'SRG-APP-000121-NDM-000238'
  tag fix_id: 'F-71017r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001493']
  tag nist: ['AU-9 a']
end
