control 'SV-55432' do
  title 'The Symantec Endpoint Protection client weekly scheduled scan must be configured to display a message to the user if a virus is detected.'
  desc "An effective awareness program explains proper rules of behavior for use of an organization's IT systems and information. Accordingly, awareness programs should include guidance to users on malware incident prevention, which can help reduce the frequency and severity of malware incidents.

Organizations should also make users aware of policies and procedures that apply to malware incident handling, such as how to identify if a host may be infected, how to report a suspected incident, and what users need to do to assist with incident handling

Having the antivirus software alert a user when a risk is detected will ensure the user is aware of the incident, and will make it possible to more closely relate the incident to any action(s) being performed by the user at the time of the detection."
  desc 'check', 'Server check:  From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> under the Notifications tab, Notifications -> Ensure "Display a notification message on the infected computer" is selected.

Criteria:  If "Display a notification message on the infected computer" is not selected, this is a finding.'
  desc 'fix', 'From the Symantec Endpoint Protection Management Server, Symantec Endpoint Protection Management Console:  Select Policies -> Double-click the applied policy -> Under Windows Settings, Scheduled Scans -> Select Administrator-Defined Scans -> Double-click the Weekly Scan -> Under the Notifications tab, Notifications -> Select "Display a notification message on the infected computer".'
  impact 0.5
  ref 'DPMS Target Symantec Endpoint Protection (SEP) 12.x - Managed'
  tag check_id: 'C-48975r2_chk'
  tag severity: 'medium'
  tag gid: 'V-42704'
  tag rid: 'SV-55432r2_rule'
  tag stig_id: 'DTASEP049'
  tag gtitle: 'DTASEP049'
  tag fix_id: 'F-48289r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
