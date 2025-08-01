control 'SV-248558' do
  title 'The OL 8 "/var/log" directory must be owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the OL 8 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the /var/log directory is owned by root with the following command:

$ sudo stat -c "%U" /var/log

root

If "root" is not returned as a result, this is a finding.'
  desc 'fix', 'Change the owner of the directory /var/log to root by running the following command:

$ sudo chown root /var/log'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51992r779238_chk'
  tag severity: 'medium'
  tag gid: 'V-248558'
  tag rid: 'SV-248558r779240_rule'
  tag stig_id: 'OL08-00-010250'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-51946r779239_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
