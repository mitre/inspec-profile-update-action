control 'SV-16751' do
  title 'Virtual switches are not labeled.'
  desc 'Virtual switches within the ESX Server require a field for the name of the switch.  This label is important since it serves as a functional descriptor for the switch,  just as physical switches require a hostname. Labeling virtual switches will indicate the function or the IP subnet of the virtual switch.  For instance, labeling the virtual switch as “internal” or some variation will indicate that the virtual switch is only for internal networking between virtual machines private virtual switch with no physical network adapters bound to it.'
  desc 'check', 'To check to see if virtual switches have labels, perform the following within VirtualCenter:

1. Log into VirtualCenter with the VI Client and select the ESX server from the inventory panel.
    The hardware configuration page for this server appears.
2. Click the Configuration tab, and click Networking.  
     Ensure that all virtual switches have a label.  If they do not,  this is a finding.'
  desc 'fix', 'Label all virtual switches.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16100r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15812'
  tag rid: 'SV-16751r1_rule'
  tag stig_id: 'ESX0230'
  tag gtitle: 'Virtual switches are not labeled.'
  tag fix_id: 'F-15765r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
