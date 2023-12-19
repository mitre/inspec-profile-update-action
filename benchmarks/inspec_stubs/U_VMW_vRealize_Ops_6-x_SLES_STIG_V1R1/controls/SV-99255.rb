control 'SV-99255' do
  title 'The /var/log directory must have mode 0750 or less permissive.'
  desc "Only authorized personnel should be aware of errors and the details of the errors. Error messages are an indicator of an organization's operational state or can identify the SLES for vRealize system or platform. Additionally, Personally Identifiable Information (PII) and operational information must not be revealed through error messages to unauthorized personnel or their designated representatives.

The structure and content of error messages must be carefully considered by the organization and development team. The extent to which the information system is able to identify and handle error conditions is guided by organizational policy and operational requirements."
  desc 'check', %q(Verify that the "/var/log" directory is the mode 0750 or less permissive by running the following command:

# ls -lad /var/log | cut -d' ' -f1

The output must look like the following example:

ls -lad /var/log | cut -d' ' -f1
drwxr-x---

If "drwxr-x---" is not returned as a result, this is a finding.)
  desc 'fix', 'Change the permissions of the directory "/var/log" to "0750" by running the following command:

# chmod 0750 /var/log'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88297r2_chk'
  tag severity: 'medium'
  tag gid: 'V-88605'
  tag rid: 'SV-99255r1_rule'
  tag stig_id: 'VROM-SL-000805'
  tag gtitle: 'SRG-OS-000206-GPOS-00084'
  tag fix_id: 'F-95347r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']
end
