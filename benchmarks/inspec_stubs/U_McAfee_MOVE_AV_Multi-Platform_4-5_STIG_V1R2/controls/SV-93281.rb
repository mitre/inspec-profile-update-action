control 'SV-93281' do
  title 'The McAfee MOVE AV SVM Settings policy must be configured to use McAfee Global Threat Intelligence file reputation with a sensitivity level of medium or higher.'
  desc 'Anti-virus software vendors use collective intelligence from sensors and cross-vector intelligence from web, email, and network threats to compile scores that reflect the likelihood of whether a file in question is malware. The collective intelligence is constantly being updated, more frequently than the typical daily anti-virus signature files. With File Reputation lookup, a more real-time response to potential malicious code is realized than with the local-running anti-virus software, since by querying the cloud-based database when a file appears to be suspicious, up-to-the-minute intelligence is provided. This type of protection reduces the threat protection time period from days to milliseconds, increases malware detection rates, and reduces downtime and remediation costs associated with malware attacks. Using File Reputation lookup is mandated by USCYBERCOM on DoD systems.'
  desc 'check', 'NOTE: This requirement is Not Applicable on the classified network.

Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under McAfee GTI, verify the "Enable McAfee GTI" check box is selected with a sensitivity level of "Medium" or higher.

If the "Enable McAfee GTI" check box is not selected or sensitivity level is lower than "Medium", this is a finding.'
  desc 'fix', 'NOTE: This requirement is Not Applicable on the classified network.

Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under McAfee GTI, select the "Enable McAfee GTI" check box. Select "Medium" or higher for sensitivity level.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE MultiPlatform Client 4.5'
  tag check_id: 'C-78145r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78575'
  tag rid: 'SV-93281r1_rule'
  tag stig_id: 'MV45-SVM-000007'
  tag gtitle: 'MV45-SVM-000007'
  tag fix_id: 'F-85311r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
