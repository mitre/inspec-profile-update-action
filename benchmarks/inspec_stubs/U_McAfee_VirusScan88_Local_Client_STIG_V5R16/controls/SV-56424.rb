control 'SV-56424' do
  title 'McAfee VirusScan Buffer Overflow Protection Buffer Overflow Settings must be configured to display a dialog box when a buffer overflow is detected.'
  desc "An effective awareness program explains proper rules of behavior for use of an organization's IT systems and information. Accordingly, awareness programs should include guidance to users on malware incident prevention, which can help reduce the frequency and severity of malware incidents.

Organizations should also make users aware of policies and procedures that apply to malware incident handling, such as how to identify if a host may be infected, how to report a suspected incident, and what users need to do to assist with incident handling.

Ensuring the antivirus software alerts the users when a Buffer Overflow is detected will ensure the user is aware of the incident and be able to more closely relate the incident to action being performed by the user at the time of the detection."
  desc 'check', 'NOTE:  Buffer Overflow Protection is not installed on 64-bit systems; this check would be Not Applicable to 64-bit systems. 

NOTE:  On 32-bit systems, when Host Intrusion Prevention is also installed, Buffer Overflow Protection will show as "Disabled because a Host Intrusion Prevention product is installed";  this check would be Not Applicable.

Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, click Task->Buffer Overflow Protection, right-click, and select Properties.

Under the Buffer Overflow Protection tab, locate the "Buffer overflow settings" label. Ensure the "Show the messages dialog box when a buffer overflow is detected" option is selected.

Criteria:  If the "Show the messages dialog box when a buffer overflow is detected" option is selected, this is not a finding. 

On the client machine, use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\McAfee\\ (32-bit)
SystemCore\\VSCore\\On Access Scanner\\BehaviourBlocking

Criteria:  If the value BOPShowMessages is 1, this is not a finding. If the value is 0, this is a finding.'
  desc 'fix', 'Access the local VirusScan console by clicking Start->All Programs->McAfee->VirusScan Console.
In the console window, under Task, click Task->Buffer Overflow Protection, right-click, and select Properties.

Under the Buffer Overflow Protection tab, locate the "Buffer overflow settings" label. Select the "Show the messages dialog box when a buffer overflow is detected" option.

Click OK to Save.'
  impact 0.5
  ref 'DPMS Target McAfee AntiVirus Locally Configured Client'
  tag check_id: 'C-49343r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14659'
  tag rid: 'SV-56424r1_rule'
  tag stig_id: 'DTAM132'
  tag gtitle: 'DTAM132-McAfee VirusScan buffer overflow message'
  tag fix_id: 'F-49147r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
