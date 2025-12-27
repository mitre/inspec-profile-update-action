control 'SV-250652' do
  title 'NTP time synchronization must be configured.'
  desc "By ensuring that all systems use the same relative time source (including the relevant localization offset), and that the relative time source can be correlated to an agreed-upon time standard (such as Coordinated Universal Time-UTC), it can make it simpler to track and correlate an intruder's actions when reviewing the relevant log files. Incorrect time settings can make it difficult to inspect and correlate log files to detect attacks, and can make auditing inaccurate."
  desc 'check', %q(From the vSphere Client:  Select the host and click "Configuration >> Time Configuration". Select the properties link and chose 'Options'. Select NTP Settings to view configured NTP servers. 

If NTP is not configured, this is a finding.)
  desc 'fix', %q(From the vSphere Client:  Select the host and click "Configuration >> Time Configuration".  Select the properties link and chose 'Options'.  From the General tab start the NTP service and select "Start and stop with host". From the NTP Settings tab click the 'Add' button to add the organization defined NTP servers.)
  impact 0.5
  ref 'DPMS Target VMWare ESXi 5-0 Server'
  tag check_id: 'C-54087r798953_chk'
  tag severity: 'medium'
  tag gid: 'V-250652'
  tag rid: 'SV-250652r798955_rule'
  tag stig_id: 'SRG-OS-99999-ESXI5-000131'
  tag gtitle: 'SRG-OS-000480-VMM-002000'
  tag fix_id: 'F-54041r798954_fix'
  tag 'documentable'
  tag legacy: ['SV-51108', 'V-39292']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
