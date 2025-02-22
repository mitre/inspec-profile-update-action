control 'SV-100381' do
  title 'The /var/log/messages file must have mode 0640 or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify that the /var/log/messages file has mode 0640 or less by running the following command:

# ls -lad /var/log/messages | cut -d' ' -f1

The output must look like the following example:

ls -lad /var/log/messages | cut -d' ' -f1
-rw-r-----

If "-rw-r-----" is not returned as a result, this is a finding.)
  desc 'fix', 'Change the permissions of the file /var/log/messages to "0640" by running the following command:

# chmod 0640 /var/log/messages'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7.x SLES'
  tag check_id: 'C-89423r1_chk'
  tag severity: 'medium'
  tag gid: 'V-89731'
  tag rid: 'SV-100381r1_rule'
  tag stig_id: 'VRAU-SL-000845'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-96473r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
