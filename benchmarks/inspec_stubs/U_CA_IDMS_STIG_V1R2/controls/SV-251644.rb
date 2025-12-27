control 'SV-251644' do
  title 'CA IDMS must prevent user code from issuing selected SVC privileged functions.'
  desc 'If an SVC is used to facilitate interpartition communication for online applications executing under other DC systems, batch application programs, and programs executed under TP monitors other than DC when running on the same LPAR, privileged functions of the SVC can be protected from these entities that do not run within the IDMS DC partition with a combination of the key specification and the disabling of selected SVC functions.'
  desc 'check', "Log on to IDMS DC system. Issue DCMT D MEM SVC+6D0 to get address of SVC options (svcopt-addr). Issue DCMT D MEM svcopt-addr. With all lengths of 1, at offset 1 is the SVC number, offset 3 contains CVKEY number, offset x' D' contains a flag byte where a setting of X'20' indicates AUTHREQ=YES. If there is no valid number for CVKEY and the flag byte of X'20' is not set, this is a finding.

Note: Offsets are subject to change."
  desc 'fix', 'Set #SVCOPT parameters CVKEY to the chosen key for startup modules and AUTHREQ=YES to create a secured SVC. Assemble, relink and install SVC. Create an entry in the Z/OS PPT for the startup module in the chosen key.

All IDMS CV startup modules must reside in an authorized library and must be linked as authorized (SETCODE AC(1)).

The IBM Z/OS parameter AllowUserKeyCsa should also be checked since the setting may impact the CVKEY choice (see TEC574934 for details).'
  impact 0.5
  ref 'DPMS Target CA IDMS'
  tag check_id: 'C-55079r807797_chk'
  tag severity: 'medium'
  tag gid: 'V-251644'
  tag rid: 'SV-251644r855282_rule'
  tag stig_id: 'IDMS-DB-000800'
  tag gtitle: 'SRG-APP-000431-DB-000388'
  tag fix_id: 'F-55033r807798_fix'
  tag 'documentable'
  tag cci: ['CCI-002530']
  tag nist: ['SC-39']
end
