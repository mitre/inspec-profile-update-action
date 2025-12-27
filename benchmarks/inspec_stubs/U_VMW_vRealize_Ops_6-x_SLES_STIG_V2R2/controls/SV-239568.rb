control 'SV-239568' do
  title 'The /var/log/messages file must be group-owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the SLES for vRealize system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify that the "/var/log/messages" file is group-owned by "root" by running the following command:

# ls -la /var/log/messages | cut -d' ' -f4

The output must look like the following example:

ls -la /var/log/messages | cut -d' ' -f4
root

If "root" is not returned as a result, this is a finding.)
  desc 'fix', 'Change the group of the file "/var/log/messages" to "root" by running the following command:

# chgrp root /var/log/messages'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42801r662153_chk'
  tag severity: 'medium'
  tag gid: 'V-239568'
  tag rid: 'SV-239568r662155_rule'
  tag stig_id: 'VROM-SL-000810'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-42760r662154_fix'
  tag 'documentable'
  tag legacy: ['SV-99257', 'V-88607']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
