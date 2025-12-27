control 'SV-219192' do
  title 'The Ubuntu operating system must configure the /var/log/syslog file to be group-owned by adm.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', 'Verify that the Ubuntu operating system configures the /var/log/syslog file to be group-owned by adm.

Check that the /var/log/syslog file is group-owned by adm with the following command:

# sudo stat -c "%n %G" /var/log/syslog
/var/log/syslog adm

If the /var/log/syslog file is not group-owned by adm, this is a finding.'
  desc 'fix', 'Configure the Ubuntu operating system to have adm group-own the /var/log/syslog file by running the following command:

# sudo chgrp adm /var/log/syslog'
  impact 0.5
  ref 'DPMS Target Canonical Ubuntu 18.04 LTS'
  tag check_id: 'C-20917r304904_chk'
  tag severity: 'medium'
  tag gid: 'V-219192'
  tag rid: 'SV-219192r610963_rule'
  tag stig_id: 'UBTU-18-010125'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-20916r304905_fix'
  tag 'documentable'
  tag legacy: ['SV-109715', 'V-100611']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
