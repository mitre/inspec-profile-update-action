control 'SV-239565' do
  title 'The /var/log directory must be group-owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the SLES for vRealize system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify the "/var/log" directory is group-owned by "root" by running the following command:

# ls -lad /var/log | cut -d' ' -f4

The output must look like the following example:

ls -lad /var/log | cut -d' ' -f4
root

If "root" is not returned as a result, this is a finding.)
  desc 'fix', 'Change the group of the directory "/var/log" to "root" by running the following command:

# chgrp root /var/log'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42798r662144_chk'
  tag severity: 'medium'
  tag gid: 'V-239565'
  tag rid: 'SV-239565r662146_rule'
  tag stig_id: 'VROM-SL-000795'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-42757r662145_fix'
  tag 'documentable'
  tag legacy: ['SV-99251', 'V-88601']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
