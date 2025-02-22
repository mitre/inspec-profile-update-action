control 'SV-240475' do
  title 'The /var/log/messages file must be group-owned by root.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify that the /var/log/messages file is group-owned by "root" by running the following command:

# ls -la /var/log/messages | cut -d' ' -f4

The output must look like the following example:

ls -la /var/log/messages | cut -d' ' -f4
root

If "root" is not returned as a result, this is a finding.)
  desc 'fix', 'Change the group of the file /var/log/messages to "root" by running the following command:

# chgrp root /var/log/messages'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43708r671164_chk'
  tag severity: 'medium'
  tag gid: 'V-240475'
  tag rid: 'SV-240475r671166_rule'
  tag stig_id: 'VRAU-SL-000835'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-43667r671165_fix'
  tag 'documentable'
  tag legacy: ['SV-100377', 'V-89727']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
