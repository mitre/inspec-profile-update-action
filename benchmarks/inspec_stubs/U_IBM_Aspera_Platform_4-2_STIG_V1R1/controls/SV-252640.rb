control 'SV-252640' do
  title 'The IBM Aspera High-Speed Transfer Server must not use the root account for transfers.'
  desc 'By incorporating a least privilege approach to the configuration of the Aspera HSTS platform, this will reduce the exposure of privileged accounts.
By default, all system users can establish a FASP connection and are only restricted by file permissions.'
  desc 'check', 'Verify the Aspera High-Speed Transfer Server restricts the use of the root account for transfers with the following command:

Warning: If an invalid user/group name is entered, the asuserdata command will return results that may appear accurate. Ensure that the user/group name is valid and entered into the command correctly.

$ sudo /opt/aspera/bin/asuserdata -u root | grep allowed | grep true

If results are returned from the above command, this is a finding.'
  desc 'fix', 'Configure the Aspera High-Speed Transfer Server to restrict the use of the root account for transfers.

For each privilege that is set to "true", run the following command:

$ sudo /opt/aspera/bin/asconfigurator -x "set_user_data;user_name,root;<privilege>,false"

Restart the IBM Aspera Node service to activate the changes.

$ sudo systemctl restart asperanoded.service'
  impact 0.5
  ref 'DPMS Target IBM Aspera Platform 4.2'
  tag check_id: 'C-56096r818088_chk'
  tag severity: 'medium'
  tag gid: 'V-252640'
  tag rid: 'SV-252640r818090_rule'
  tag stig_id: 'ASP4-TS-020240'
  tag gtitle: 'SRG-NET-000132-ALG-000087'
  tag fix_id: 'F-56046r818089_fix'
  tag 'documentable'
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
