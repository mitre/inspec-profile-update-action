control 'SV-253275' do
  title 'Internet Information System (IIS) or its subcomponents must not be installed on a workstation.'
  desc 'IIS is not installed by default. Installation of Internet Information System (IIS) may allow unauthorized internet services to be hosted. Websites must only be hosted on servers that have been designed for that purpose and can be adequately secured.'
  desc 'check', 'Verify it has not been installed on the system.

Run "Programs and Features".
Select "Turn Windows features on or off".

If the entries for "Internet Information Services" or "Internet Information Services Hostable Web Core" are selected, this is a finding.

If an application requires IIS or a subset to be installed to function, this needs be documented with the ISSO. In addition, any applicable requirements from the IIS STIG must be addressed.'
  desc 'fix', 'Uninstall "Internet Information Services" or "Internet Information Services Hostable Web Core" from the system.'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56728r828907_chk'
  tag severity: 'high'
  tag gid: 'V-253275'
  tag rid: 'SV-253275r828909_rule'
  tag stig_id: 'WN11-00-000100'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-56678r828908_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
