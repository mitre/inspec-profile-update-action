control 'SV-254195' do
  title 'Nutanix AOS must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new accounts are created they do not have unnecessary access.'
  desc 'check', 'Confirm Nutanix AOS defines default permissions for all authenticated users in such a way that the user can only read and modify their own files.

$ sudo grep -i umask /etc/login.defs
UMASK 077

If the value for the "UMASK" parameter is not "077", or the "UMASK" parameter is missing or is commented out, this is a finding.'
  desc 'fix', 'Configure Nutanix AOS default permissions UMASK to 077 by running the following command.

salt-call state.sls security/CVM/shellCVM'
  impact 0.3
  ref 'DPMS Target Nutanix AOS 5.20.x OS'
  tag check_id: 'C-57680r846671_chk'
  tag severity: 'low'
  tag gid: 'V-254195'
  tag rid: 'SV-254195r846673_rule'
  tag stig_id: 'NUTX-OS-001080'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag fix_id: 'F-57631r846672_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
