control 'SV-30694' do
  title 'If a data spill (Classified Message Incident (CMI)) occurs on a mobile device, the site must follow required data spill procedures.'
  desc 'If required procedures are not followed after a data spill, classified data could be exposed to unauthorized personnel.'
  desc 'check', 'Detailed Policy Requirements: 
This requirement applies to mobile operating system (OS)  mobile devices.

This requirement also applies to sensitive DoD information stored on mobile OS devices that are not authorized to connect to DoD networks or store/process sensitive DoD information. Sensitive DoD data or information is defined as any data/information that has not been approved for public release by the site/Command Public Affairs Officer (PAO).

If a data spill occurs on a  mobile device, the following actions must be completed: 

- The  mobile device management server and email servers (i.e., Exchange, Oracle mail, etc.) are handled as classified systems until they are sanitized according to appropriate procedures. (See NSA/CSS Storage Device Declassification Manual 9-12 for sanitization procedures.)

- The  mobile device is handled as a classified device and destroyed according to DoD guidance for destroying classified equipment or sanitized as directed in Check WIR-SPP-003-01. 

Check Procedures: 
Interview the ISSO. Determine if the site has had a data spill within the previous 24 months. If yes, review written records, incident reports, and/or after action reports and determine if required procedures were followed. 

If the site had a data spill within the previous 24 months and required procedures were not followed, this is a finding.'
  desc 'fix', 'Follow required procedures after a data spill occurs.'
  impact 0.7
  ref 'DPMS Target MDM Server Policy'
  tag check_id: 'C-31115r9_chk'
  tag severity: 'high'
  tag gid: 'V-24957'
  tag rid: 'SV-30694r6_rule'
  tag stig_id: 'WIR-SPP-003-02'
  tag gtitle: 'Site must follow required data spill procedures'
  tag fix_id: 'F-27583r4_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
end
