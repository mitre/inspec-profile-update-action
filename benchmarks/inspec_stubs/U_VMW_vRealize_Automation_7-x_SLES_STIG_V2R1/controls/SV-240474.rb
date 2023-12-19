control 'SV-240474' do
  title 'The /var/log directory must have mode 0750 or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the operating system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify that the /var/log directory has mode 0750 or less by running the following command:

# ls -lad /var/log | cut -d' ' -f1

The output must look like the following example:

ls -lad /var/log | cut -d' ' -f1
drwxr-x---

If "drwxr-x---" is not returned as a result, this is a finding.)
  desc 'fix', 'Change the permissions of the directory /var/log to "0750" by running the following command:

# chmod 0750 /var/log'
  impact 0.5
  ref 'DPMS Target VMware vRealize Automation 7-x SLES'
  tag check_id: 'C-43707r671161_chk'
  tag severity: 'medium'
  tag gid: 'V-240474'
  tag rid: 'SV-240474r671163_rule'
  tag stig_id: 'VRAU-SL-000830'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-43666r671162_fix'
  tag 'documentable'
  tag legacy: ['SV-100375', 'V-89725']
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
