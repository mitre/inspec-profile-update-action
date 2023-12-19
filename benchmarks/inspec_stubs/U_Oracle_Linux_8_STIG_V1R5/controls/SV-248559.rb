control 'SV-248559' do
  title 'The OL 8 "/var/log" directory must be group-owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the OL 8 system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives. 
 
The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify the "/var/log" directory is group-owned by root with the following command:

$ sudo stat -c "%G" /var/log

root

If "root" is not returned as a result, this is a finding.'
  desc 'fix', 'Change the group of the directory "/var/log" to "root" by running the following command:

$ sudo chgrp root /var/log'
  impact 0.5
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-51993r779241_chk'
  tag severity: 'medium'
  tag gid: 'V-248559'
  tag rid: 'SV-248559r779243_rule'
  tag stig_id: 'OL08-00-010260'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-51947r779242_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
