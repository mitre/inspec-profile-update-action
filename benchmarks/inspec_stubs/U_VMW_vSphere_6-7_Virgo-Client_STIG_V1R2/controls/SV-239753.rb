control 'SV-239753' do
  title 'vSphere Client application files must be verified for their integrity.'
  desc 'Verifying that vSphere Client application code is unchanged from its shipping state is essential for file validation and non-repudiation of vSphere Client. There is no reason that the MD5 hash of the rpm original files should be changed after installation, excluding configuration files.'
  desc 'check', 'At the command prompt, execute the following command:

# rpm -V vsphere-client|grep "^..5......"|grep -E "\\.war|\\.jar|\\.sh|\\.py"

If there is any output, this is a finding.'
  desc 'fix', 'Reinstall the VCSA or roll back to a snapshot. 

Modifying the vSphere Client installation files manually is not supported by VMware.'
  impact 0.5
  ref 'DPMS Target VMware vSphere 6.7 Virgo-Client'
  tag check_id: 'C-42986r679484_chk'
  tag severity: 'medium'
  tag gid: 'V-239753'
  tag rid: 'SV-239753r879584_rule'
  tag stig_id: 'VCFL-67-000012'
  tag gtitle: 'SRG-APP-000131-WSR-000051'
  tag fix_id: 'F-42945r679485_fix'
  tag 'documentable'
  tag cci: ['CCI-001749']
  tag nist: ['CM-5 (3)']
end
