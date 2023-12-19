control 'SV-16752' do
  title 'Virtual switch labels begin with a number.'
  desc 'Virtual switches within the ESX Server require a field for the name of the switch.  This label is important since it serves as a functional descriptor for the switch.  The labels of the virtual switches will not contain a number as the first character, since there have been known issues in the past that have caused erratic behavior.  This has been especially true when renaming or removing the virtual switch. Labeling virtual switches will indicate the function or the IP subnet of the virtual switch.  For instance, labeling the virtual switch as “internal” or some variation will indicate that the switch is only for internal networking between virtual machines private virtual switch with no physical network adapters bound to it.'
  desc 'check', 'To check to see if virtual switches have labels, perform the following within VirtualCenter:

1. Log into VirtualCenter with the VI Client and select the ESX server from the inventory panel.
    The hardware configuration page for this server appears.
2. Click the Configuration tab, and click Networking.  
     Ensure that all virtual switches have a label that does not start with a number.   If the virtual switches begin with a number, this is a finding.'
  desc 'fix', 'Do not begin virtual switch labels with a number.'
  impact 0.5
  ref 'DPMS Target VMware VirtualCenter'
  tag check_id: 'C-16103r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15813'
  tag rid: 'SV-16752r1_rule'
  tag stig_id: 'ESX0240'
  tag gtitle: 'Virtual switch labels begin with a number.'
  tag fix_id: 'F-15766r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer', '[Virtual Server Administrator]']
end
