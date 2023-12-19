control 'SV-248557' do
  title 'The OL 8 "/var/log" directory must have mode 0755 or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the OL 8 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that the "/var/log" directory has a mode of "0755" or less with the following command:

$ sudo stat -c "%a %n" /var/log

755 /var/log

If a value of "0755" or less permissive is not returned, this is a finding.'
  desc 'fix', 'Change the permissions of the directory "/var/log" to "0755" by running the following command:

$ sudo chmod 0755 /var/log'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51991r779235_chk'
  tag severity: 'medium'
  tag gid: 'V-248557'
  tag rid: 'SV-248557r779237_rule'
  tag stig_id: 'OL08-00-010240'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-51945r779236_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
