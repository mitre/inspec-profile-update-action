control 'SV-25253' do
  title 'Internet Information System (IIS) or its subcomponents must not be installed on a workstation.'
  desc 'Installation of Internet Information System (IIS) may allow unauthorized internet services to be hosted.  Websites must only be hosted on servers that have been designed for that purpose and can be adequately secured.'
  desc 'check', 'To verify whether IIS is installed, perform the following:

Open Control Panel.
Select "Programs and Features".
Select "Turn Windows features on or off".

If the entry for "Internet Information Services" is selected, this is a finding.

If an application requires IIS or a subset to be installed to function, this needs be documented with the ISSO.  In addition, any applicable requirements from the IIS STIG must be addressed.'
  desc 'fix', 'Remove "Internet Information Services" from the system.'
  impact 0.7
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-62073r1_chk'
  tag severity: 'high'
  tag gid: 'V-3347'
  tag rid: 'SV-25253r2_rule'
  tag gtitle: 'Internet Information System (IIS)'
  tag fix_id: 'F-66971r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
