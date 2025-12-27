control 'SV-248554' do
  title 'The OL 8 "/var/log/messages" file must have mode 0640 or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the OL 8 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that the "/var/log/messages" file has mode "0640" or less permissive with the following command: 
 
$ sudo stat -c "%a %n" /var/log/messages 
 
640 /var/log/messages 
 
If a value of "0640" or less permissive is not returned, this is a finding.'
  desc 'fix', 'Change the permissions of the file "/var/log/messages" to "0640" by running the following command: 
 
$ sudo chmod 0640 /var/log/messages'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51988r779226_chk'
  tag severity: 'medium'
  tag gid: 'V-248554'
  tag rid: 'SV-248554r779228_rule'
  tag stig_id: 'OL08-00-010210'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-51942r779227_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
