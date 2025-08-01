control 'SV-254175' do
  title 'Nutanix AOS must produce audit records containing the full-text recording of successful and unsuccessful attempts to execute the opensshrelated privileged commands.'
  desc 'Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.

At a minimum, the organization must audit the full-text recording of privileged commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.'
  desc 'check', 'Verify Nutanix AOS generates audit records when successful/unsuccessful attempts to use the following commands occur.

Check that the following system call is being audited by performing the following command to check the file system rules in "/etc/audit/audit.rules":

$ sudo grep -iw /usr/libexec/openssh/ssh-keysign /etc/audit/audit.rules
If the output is not -a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F auid>=1000 -F auid!=4294967295 -k privileged, this is a finding.'
  desc 'fix', 'Configure the audit rules by running the following command:

$ sudo salt-call state.sls security/CVM/auditCVM'
  impact 0.5
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57660r846611_chk'
  tag severity: 'medium'
  tag gid: 'V-254175'
  tag rid: 'SV-254175r846613_rule'
  tag stig_id: 'NUTX-OS-000730'
  tag gtitle: 'SRG-OS-000042-GPOS-00020'
  tag fix_id: 'F-57611r846612_fix'
  tag 'documentable'
  tag cci: ['CCI-000135']
  tag nist: ['AU-3 (1)']
end
