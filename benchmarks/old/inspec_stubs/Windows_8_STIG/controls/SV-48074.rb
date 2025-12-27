control 'SV-48074' do
  title 'Internet Information System (IIS) or its subcomponents must not be installed on a workstation.'
  desc 'Installation of Internet Information System (IIS) may allow unauthorized internet services to be hosted.  Websites must only be hosted on servers that have been designed for that purpose and can be adequately secured.'
  desc 'check', 'Verify IIS is not installed by performing the following:

Search for "Features".
Select "Turn Windows features on or off".

If the entries for "Internet Information Services" or "Internet Information Services Hostable Web Core" are selected, this is a finding.

If an application requires IIS or a subset to be installed to function, this needs be documented with the ISSO.  In addition, any applicable requirements from the IIS STIG must be addressed.'
  desc 'fix', 'Remove "Internet Information Services" or "Internet Information Services Hostable Web Core" from the system.'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44813r3_chk'
  tag severity: 'high'
  tag gid: 'V-3347'
  tag rid: 'SV-48074r2_rule'
  tag stig_id: 'WN08-GE-000016'
  tag gtitle: 'Internet Information System (IIS)'
  tag fix_id: 'F-41212r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
