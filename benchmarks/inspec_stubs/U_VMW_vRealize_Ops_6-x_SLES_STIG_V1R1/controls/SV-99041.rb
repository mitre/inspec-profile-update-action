control 'SV-99041' do
  title 'The SLES for vRealize must protect audit information from unauthorized deletion - log directories.'
  desc 'If audit information were to become compromised, then forensic analysis and discovery of the true source of potentially malicious system activity is impossible to achieve.

To ensure the veracity of audit information, the SLES for vRealize must protect audit information from unauthorized deletion. This requirement can be achieved through multiple methods, which will depend upon system architecture and design.

Audit information includes all information (e.g., audit records, audit settings, audit reports) needed to successfully audit information system activity.'
  desc 'check', %q(Run the following command to check the mode of the system audit directories: 

# grep "^log_file" /etc/audit/auditd.conf|sed 's/^[^/]*//; s/[^/]*$//'|xargs stat -c %a:%n

Audit directories must be mode "0700". 

If the audit directories is not set to mode "0700", this is a finding.)
  desc 'fix', 'Change the mode of the audit log directories with the following command: 

# chmod 700 <audit log directory>'
  impact 0.5
  ref 'DPMS Target VMware vRealize Operations Manager 6.x SLES'
  tag check_id: 'C-88083r1_chk'
  tag severity: 'medium'
  tag gid: 'V-88391'
  tag rid: 'SV-99041r1_rule'
  tag stig_id: 'VROM-SL-000170'
  tag gtitle: 'SRG-OS-000059-GPOS-00029'
  tag fix_id: 'F-95133r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000164']
  tag nist: ['AU-9 a']
end
