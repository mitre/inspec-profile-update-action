control 'SV-239569' do
  title 'The /var/log/messages file must be owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the SLES for vRealize system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify that the "/var/log/messages" file is owned by "root" by running the following command:

# ls -la /var/log/messages | cut -d' ' -f3

The output must look like the following example:

ls -la /var/log/messages | cut -d' ' -f3
root

If "root" is not returned as a result, this is a finding.)
  desc 'fix', 'Change the owner of the file "/var/log/messages" to "root" by running the following command:

# chown root /var/log/messages'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6-x SLES'
  tag check_id: 'C-42802r662156_chk'
  tag severity: 'medium'
  tag gid: 'V-239569'
  tag rid: 'SV-239569r662158_rule'
  tag stig_id: 'VROM-SL-000815'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-42761r662157_fix'
  tag 'documentable'
  tag legacy: ['SV-99259', 'V-88609']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
