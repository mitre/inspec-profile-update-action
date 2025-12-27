control 'SV-56369' do
  title 'McAfee VirusScan On-Access Scanner General Settings must be configured to notify local users when detections occur.'
  desc "An effective awareness program explains proper rules of behavior for use of an organization's IT systems and information. Accordingly, awareness programs should include guidance to users on malware incident prevention, which can help reduce the frequency and severity of malware incidents.

Organizations should also make users aware of policies and procedures that apply to malware incident handling, such as how to identify if a host may be infected, how to report a suspected incident, and what users need to do to assist with incident handling

Ensuring the antivirus software alerts the users when malware is detected will ensure the user is informed of the incident and be able to more closely relate the incident to action being performed by the user at the time of the detection."
  desc 'check', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.

Under the Messages tab, locate the "Message for local users:" label. Ensure the "Show the messages dialog box when a threat is detected and display the specified text in the message" option is selected.

Criteria:  If the "Show the messages dialog box when a threat is detected and display the specified text in the message" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
HKLM\\Software\\Wow6432Node\\McAfee\\ (64-bit) 
SystemCore\\VSCore\\On Access Scanner\\McShield\\Configuration

Criteria:  If the value of Alert_AutoShowList is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console
On the menu bar, click Task->On-Access Scanner Properties.
Select the General Settings.
Under the Messages tab, locate the "Messages for local users:" label. Select the "Show the messages dialog box when a threat is detected and display the specified text in the message" option. 

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49295r1_chk'
  tag severity: 'medium'
  tag gid: 'V-6469'
  tag rid: 'SV-56369r1_rule'
  tag stig_id: 'DTAM004'
  tag gtitle: 'DTAM004-McAfee VirusScan message dialog'
  tag fix_id: 'F-49050r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
