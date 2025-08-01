control 'SV-75245' do
  title 'The Google Search Appliance must employ automated mechanisms to alert security personnel of inappropriate or unusual activities with security implications.'
  desc 'Applications will typically utilize logging mechanisms for maintaining a historical log of activity that occurs within the application.  This information can then be used for diagnostic purposes, forensics purposes or other purposes relevant to ensuring the availability and integrity of the application.  

While it is important to log events identified as being critical and relevant to security, it is equally important to notify the appropriate personnel in a timely manner so they are able to respond to events as they occur.

Solutions that include a manual notification procedure do not offer the reliability and speed of an automated notification solution. Applications must employ automated mechanisms to alert security personnel of inappropriate or unusual activities that have security implications.  If this capability is not built directly into the application, the application must be able to integrate with existing security infrastructure that provides this capability.'
  desc 'check', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "System Settings".

If "Enable Daily Status Email Messages" is checked and a valid administrator email address is entered, this is not a finding.'
  desc 'fix', 'Open the GSA Web Admin Console at https:<your GSA IP or hostname>:8443.

Login to the GSA management interface.
  
Navigate to "Administration", select "System Settings".

Select "Enable Daily Status Email Messages" and enter a valid administrator email address.'
  impact 0.5
  ref 'DPMS Target Google Search Appliance v3.1'
  tag check_id: 'C-61717r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60793'
  tag rid: 'SV-75245r1_rule'
  tag stig_id: 'GSAP-00-000820'
  tag gtitle: 'SRG-APP-000237'
  tag fix_id: 'F-66475r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001274']
  tag nist: ['SI-4 (12)']
end
