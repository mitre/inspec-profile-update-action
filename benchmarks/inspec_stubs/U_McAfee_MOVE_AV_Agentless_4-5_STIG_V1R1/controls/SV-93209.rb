control 'SV-93209' do
  title 'The McAfee MOVE AV SVM Settings policy must be configured to use McAfee Global Threat Intelligence File Reputation with a sensitivity level of medium or higher.'
  desc 'Anti-virus software vendors use collective intelligence from sensors and cross-vector intelligence from web, email, and network threats to compile scores that reflect the likelihood of whether a file in question is malware. The collective intelligence is constantly being updated, more frequently than the typical daily anti-virus signature files. 

With File Reputation lookup, a more real-time response to potential malicious code is realized than with the local-running anti-virus software, since by querying the cloud-based database when a file appears to be suspicious, up-to-the-minute intelligence is provided. This type of protection reduces the threat protection time period from days to milliseconds, increases malware detection rates, and reduces downtime and remediation costs associated with malware attacks. Using File Reputation lookup is mandated by USCYBERCOM on DoD systems.'
  desc 'check', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "McAfee GTI", verify the "Enable McAfee GTI" check box is selected with a sensitivity level of "Medium" or higher.

If the "Enable McAfee GTI" check box is not selected or the sensitivity level is lower than "Medium", this is a finding.'
  desc 'fix', 'Access the McAfee ePO console.

Select Menu >> Policy >> Policy Catalog and then select "MOVE AntiVirus 4.5.0" from the Product list.

From the Category list, select "SVM Settings".

Select each configured SVM Settings policy.

Click "Show Advanced".

Under "McAfee GTI", select the "Enable McAfee GTI" check box. Select "Medium" or higher for sensitivity level.

Click "Save".'
  impact 0.5
  ref 'DPMS Target McAfee MOVE Agentless 4.5 SVM'
  tag check_id: 'C-78065r1_chk'
  tag severity: 'medium'
  tag gid: 'V-78503'
  tag rid: 'SV-93209r1_rule'
  tag stig_id: 'MV45-SVM-200007'
  tag gtitle: 'MV45-SVM-200007'
  tag fix_id: 'F-85237r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
