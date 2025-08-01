control 'SV-248649' do
  title 'Unattended or automatic logon via the OL 8 graphical user interface must not be allowed.'
  desc 'Failure to restrict system access to authenticated users negatively impacts operating system security.'
  desc 'check', 'Note: This requirement assumes the use of the OL 8 default graphical user interface, Gnome Shell. If the system does not have any graphical user interface installed, this requirement is Not Applicable. 

Verify the operating system does not allow an unattended or automatic logon to the system via a graphical user interface. 

Check for the value of "AutomaticLoginEnable" in the "/etc/gdm/custom.conf" file with the following command: 
 
$ sudo grep -i automaticloginenable /etc/gdm/custom.conf 
 
AutomaticLoginEnable=false 
 
If the value of "AutomaticLoginEnable" is not set to "false", this is a finding.'
  desc 'fix', 'Configure OL 8 to not allow an unattended or automatic logon to the system via a graphical user interface. 
 
Add or edit the line for the "AutomaticLoginEnable" parameter in the [daemon] section of the "/etc/gdm/custom.conf" file to "false": 
 
[daemon] 
AutomaticLoginEnable=false'
  impact 0.7
  ref 'DPMS Target Oracle Linux 8'
  tag check_id: 'C-52083r779511_chk'
  tag severity: 'high'
  tag gid: 'V-248649'
  tag rid: 'SV-248649r779513_rule'
  tag stig_id: 'OL08-00-010820'
  tag gtitle: 'SRG-OS-000480-GPOS-00229'
  tag fix_id: 'F-52037r779512_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
