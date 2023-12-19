control 'SV-251550' do
  title 'Firefox must be configured to not automatically execute or download MIME types that are not authorized for auto-download.'
  desc 'Some files can be downloaded or execute without user interaction. This setting ensures these files are not downloaded and executed.'
  desc 'check', 'Type "about:preferences" in the browser address bar. 

Type "Applications" in the Find bar in the upper-right corner. 

Determine if any of the following file extensions are listed: HTA, JSE, JS, MOCHA, SHS, VBE, VBS, SCT, WSC, FDF, XFDF, LSL, LSO, LSS, IQY, RQY, DOS, BAT, PS, EPS, WCH, WCM, WB1, WB3, WCH, WCM, AD.

If the entry exists and the "Action" is "Save File" or "Always Ask", this is not a finding.
 
If an extension exists and the entry in the Action column is associated with an application that does/can execute the code, this is a finding.'
  desc 'fix', 'Remove any unauthorized extensions from the auto-download list.'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54985r832304_chk'
  tag severity: 'medium'
  tag gid: 'V-251550'
  tag rid: 'SV-251550r832305_rule'
  tag stig_id: 'FFOX-00-000006'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-54939r807121_fix'
  tag 'documentable'
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
