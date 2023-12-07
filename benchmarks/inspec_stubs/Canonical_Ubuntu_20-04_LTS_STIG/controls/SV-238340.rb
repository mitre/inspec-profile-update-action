control 'SV-238340' do
  title 'The Ubuntu operating system must configure the /var/log directory to have mode 0750 or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that the Ubuntu operating system configures the "/var/log" directory with a mode of 750 or less permissive with the following command: 
 
$ stat -c "%n %a" /var/log 
 
/var/log 750 
 
If a value of "750" or less permissive is not returned, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to have permissions of 0750 for the "/var/log" directory by running the following command: 
 
$ sudo chmod 0750 /var/log'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 20.04 LTS'
  tag check_id: 'C-41550r654193_chk'
  tag severity: 'medium'
  tag gid: 'V-238340'
  tag rid: 'SV-238340r654195_rule'
  tag stig_id: 'UBTU-20-010419'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-41509r654194_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
