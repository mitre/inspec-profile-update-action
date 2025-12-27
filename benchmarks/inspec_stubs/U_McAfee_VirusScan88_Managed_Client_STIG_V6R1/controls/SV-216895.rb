control 'SV-216895' do
  title 'McAfee VirusScan On-Access General Policies must be configured to notify local users when detections occur.'
  desc %q("An effective awareness program explains proper rules of behavior for use of an organization's IT systems and information. Accordingly, awareness programs should include guidance to users on malware incident prevention, which can help reduce the frequency and severity of malware incidents.

Organizations should also make users aware of policies and procedures that apply to malware incident handling, such as how to identify if a host may be infected, how to report a suspected incident, and what users need to do to assist with incident handling.

Ensuring the antivirus software alerts the users when malware is detected will ensure the user is informed of the incident and be able to more closely relate the incident to actions being performed by the user at the time of the detection.")
  desc 'check', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the Messages tab, locate the "User message:" label. Ensure the "Show the messages dialog box when a threat is detected and display the specified text in the message" option is selected.

Criteria:  If the "Show the messages dialog box when a threat is detected and display the specified text in the message" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit)
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria:  If the value of Alert_AutoShowList is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'From the ePO server console System Tree, select the Systems tab, select the asset to be checked, select Actions, select Agent, and select Modify Policies on a Single System. From the product pull down list, select VirusScan Enterprise 8.8.0. Select from the Policy column the policy associated with the On-Access General Policies. Under the Messages tab, locate the "User message:" label. Select the "Show the messages dialog box when a threat is detected and display the specified text in the message" option. Select Save.'
  impact 0.5
  ref 'DPMS Target McAfee VirusScan 8.8 Managed Client'
  tag check_id: 'C-18125r309414_chk'
  tag severity: 'medium'
  tag gid: 'V-216895'
  tag rid: 'SV-216895r397642_rule'
  tag stig_id: 'DTAM004'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-18123r309415_fix'
  tag 'documentable'
  tag legacy: ['SV-55141', 'V-6469']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
