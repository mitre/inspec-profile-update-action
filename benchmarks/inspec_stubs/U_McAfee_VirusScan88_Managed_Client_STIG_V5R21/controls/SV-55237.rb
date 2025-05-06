control 'SV-55237' do
  title 'McAfee VirusScan Buffer Overflow Protection Policies must be configured to display a dialog box when a buffer overflow is detected.'
  desc "An effective awareness program explains proper rules of behavior for use of an organization's IT systems and information. Accordingly, awareness programs should include guidance to users on malware incident prevention, which can help reduce the frequency and severity of malware incidents.

Organizations should also make users aware of policies and procedures that apply to malware incident handling, such as how to identify if a host may be infected, how to report a suspected incident, and what users need to do to assist with incident handling.

Ensuring the antivirus software alerts the users when a buffer overflow is detected will ensure the user is aware of the incident and be able to more closely relate the incident to actions being performed by the user at the time of the detection."
  desc 'check', 'NOTE:  Buffer Overflow Protection is not installed on 64-bit systems; this check would be Not Applicable to 64-bit systems. 

NOTE:  On 32-bit systems, when Host Intrusion Prevention is also installed, Buffer Overflow Protection will show as "Disabled because a Host Intrusion Prevention product is installed"; this check would be Not Applicable.

From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the Buffer Overflow Protection Policies. Under the Buffer Overflow Protection tab, locate the "Client system warning:" label. Ensure the "Show the messages dialog box when a buffer overflow is detected" option is selected.

Criteria:  If the "Show the messages dialog box when a buffer overflow is detected" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria:  If the value BOPShowMessages is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the Buffer Overflow Protection Policies. Under the Buffer Overflow Protection tab, locate the "Client system warning:" label. Select the "Show the messages dialog box when a buffer overflow is detected" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan Enterprise 8.8 - Managed Client'
  tag check_id: 'C-48827r3_chk'
  tag severity: 'medium'
  tag gid: 'V-14659'
  tag rid: 'SV-55237r1_rule'
  tag stig_id: 'DTAM132'
  tag gtitle: 'DTAM132-McAfee VirusScan buffer overflow message'
  tag fix_id: 'F-48092r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
